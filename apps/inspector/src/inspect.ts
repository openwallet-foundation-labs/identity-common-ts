import { parseAccessCertificate, validateAccessCertificate } from '@owf/eudi-access-certificate'
import { LOTE_VALIDATION_CODES, LoTEProfile, validateLoTE, validateLoTEProfile } from '@owf/eudi-lote'
import { normalizeWRPRCPayload, validateWRPRC } from '@owf/eudi-registration-certificate'
import {
  parseTrustedList,
  TrustedListProfiles,
  TSLType,
  validateTrustedList,
  validateTrustedListProfile,
  verifyEuLotlSignature,
  verifyTrustedListSignature,
} from '@owf/eudi-tl'
import { base64, base64url, decodeJwt, type Finding, hex } from '@owf/identity-common'
import { validateStatusListJwt } from '@owf/token-status-list'

import { type Inspection, InspectionError } from './inspection'
import { inspectMdoc, isCborMap } from './mdoc'
import { inspectSdJwt, isSdJwt } from './sd-jwt'

export { type DocumentKind, type Inspection, InspectionError } from './inspection'

const JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/
const HEX = /^(?:[0-9a-fA-F]{2})+$/
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/
const BASE64URL = /^[A-Za-z0-9_-]+$/

/**
 * Recognise the format of the input, parse it and check it against its specification.
 *
 * @throws InspectionError when the input is not one of the supported formats or does not parse
 */
export function inspect(input: string | Uint8Array): Inspection {
  if (typeof input !== 'string' && isBinary(input)) return inspectBinary(input)

  const text = (typeof input === 'string' ? input : new TextDecoder().decode(input)).replace(/^﻿/, '').trim()
  if (!text) throw new InspectionError('There is nothing to inspect')
  if (text.startsWith('<')) return inspectTrustedList(text)
  if (text.includes('-----BEGIN CERTIFICATE-----')) return inspectAccessCertificate(text)
  if (text.startsWith('{')) return inspectJson(text)
  if (isSdJwt(text)) return inspectSdJwt(text)
  if (JWS.test(text)) return inspectJws(text)

  // A certificate or an mdoc as text
  const compact = text.replace(/\s+/g, '')
  const unpadded = compact.replace(/=+$/, '')
  const decode = (decoder: () => Uint8Array) => {
    try {
      return decoder()
    } catch (error) {
      throw new InspectionError(`The input cannot be decoded: ${errorMessage(error)}`)
    }
  }
  if (HEX.test(compact)) return inspectBinary(decode(() => hex.decode(compact)))
  if (BASE64URL.test(unpadded)) return inspectBinary(decode(() => base64url.decode(unpadded)))
  if (BASE64.test(compact)) return inspectBinary(decode(() => base64.decode(compact)))

  throw new InspectionError(
    'Unrecognised input. Expected a trusted list (XML), a LoTE (JSON or JWS), a registration certificate or status list (JWT), an SD-JWT, an mdoc (CBOR as hex or base64url) or a certificate (PEM, base64 or DER).'
  )
}

// DER starts with a SEQUENCE and an mdoc with a CBOR map, which no supported text format does
const isBinary = (bytes: Uint8Array) => bytes[0] === 0x30 || isCborMap(bytes)

function inspectBinary(bytes: Uint8Array): Inspection {
  if (bytes[0] === 0x30) return inspectAccessCertificate(bytes)
  if (isCborMap(bytes)) return inspectMdoc(bytes)
  throw new InspectionError('The decoded bytes are neither a DER certificate nor the CBOR of an mdoc')
}

const errorMessage = (error: unknown) => (error instanceof Error ? error.message : String(error))

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const sameUri = (a: string | undefined, b: string | undefined) =>
  (a ?? '').replace(/^https?:\/\//, '') === (b ?? '').replace(/^https?:\/\//, '')

const findingKey = (finding: Finding) => `${finding.code}|${finding.path.join('.')}`

const withPathPrefix = (prefix: string, findings: Finding[]): Finding[] =>
  findings.map((finding) => ({ ...finding, path: [prefix, ...finding.path] }))

function inspectTrustedList(xml: string): Inspection {
  let trustedList: ReturnType<typeof parseTrustedList>
  try {
    trustedList = parseTrustedList(xml)
  } catch (error) {
    throw new InspectionError(`This XML is not a parsable ETSI TS 119 612 trusted list: ${errorMessage(error)}`)
  }

  const structure = validateTrustedList(trustedList)
  const findings = [...structure.findings]
  const checks = ['ETSI TS 119 612 structure']
  const notes: string[] = []

  const profile = Object.values(TrustedListProfiles).find((rule) => sameUri(rule.tslType, trustedList.tslType))
  if (!profile) {
    notes.push(`No profile check, as the TSLType ${trustedList.tslType ?? '(none)'} is not one of a known profile`)
  } else if (!structure.valid) {
    notes.push(`The ${profile.name} profile is not checked, as the structure is invalid`)
  } else {
    checks.push(`${profile.name} profile`)
    findings.push(...validateTrustedListProfile(trustedList, profile).findings)
  }

  const isLotl = sameUri(trustedList.tslType, TSLType.EUlistofthelists)
  return {
    kind: 'trusted-list',
    title: isLotl ? 'EU List of Trusted Lists' : 'Trusted list (ETSI TS 119 612)',
    checks,
    notes,
    value: trustedList,
    findings,
    verifySignature: async () => {
      if (isLotl) {
        await verifyEuLotlSignature(xml)
        return 'Valid, and signed with one of the EU LOTL signing certificates shipped with @owf/eudi-tl.'
      }
      await verifyTrustedListSignature(xml)
      return 'Valid. This proves integrity only: the signer certificate is not compared with the one the LOTL points to.'
    },
  }
}

function inspectJson(text: string): Inspection {
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch (error) {
    throw new InspectionError(`Invalid JSON: ${errorMessage(error)}`)
  }
  if (isRecord(value) && 'LoTE' in value) return inspectLoTE(value)
  throw new InspectionError('This JSON is not a LoTE document, as it has no LoTE property')
}

function inspectJws(jws: string): Inspection {
  let decoded: { header: Record<string, unknown>; payload: Record<string, unknown> }
  try {
    decoded = decodeJwt<Record<string, unknown>, Record<string, unknown>>(jws)
  } catch (error) {
    throw new InspectionError(`This looks like a JWS, but it cannot be decoded: ${errorMessage(error)}`)
  }

  const { header, payload } = decoded
  const typ = typeof header.typ === 'string' ? header.typ.toLowerCase().replace(/^application\//, '') : undefined
  if (typ === 'rc-wrp+jwt') return inspectRegistrationCertificate(header, payload)
  if (typ === 'dc+sd-jwt' || typ === 'vc+sd-jwt') return inspectSdJwt(jws)
  if (typ === 'statuslist+jwt' || 'status_list' in payload) return inspectStatusList(header, payload)
  if ('LoTE' in payload) return inspectLoTE(payload, header)
  throw new InspectionError(
    `This JWS has the typ ${String(header.typ ?? '(none)')} and is neither a registration certificate (rc-wrp+jwt), a status list (statuslist+jwt) nor a LoTE`
  )
}

function inspectLoTE(document: Record<string, unknown>, header?: Record<string, unknown>): Inspection {
  const structure = validateLoTE(document)
  const findings = [...structure.findings]
  const checks = ['ETSI TS 119 602 structure']
  const notes: string[] = []

  // Only the profile of the LoTEType reports more than a LoTEType mismatch
  const matched = Object.values(LoTEProfile)
    .map((profile) => ({ profile, result: validateLoTEProfile(document, profile) }))
    .find(
      ({ result }) =>
        result.valid || result.findings.some((finding) => finding.code !== LOTE_VALIDATION_CODES.UNEXPECTED_LOTE_TYPE)
    )
  if (matched) {
    checks.push(`${matched.profile} profile`)
    // The profile schemas extend the structure schema, so skip what it already reported
    const reported = new Set(findings.map(findingKey))
    findings.push(...matched.result.findings.filter((finding) => !reported.has(findingKey(finding))))
  } else {
    notes.push('No profile check, as the LoTEType is not the one of an EU profile')
  }
  notes.push(header ? 'The JAdES signature is not verified' : 'Unsigned JSON, so there is no signature to verify')

  return {
    kind: 'lote',
    title: 'List of Trusted Entities (ETSI TS 119 602)',
    checks,
    notes,
    value: header ? { header, payload: document } : document,
    findings: header ? withPathPrefix('payload', findings) : findings,
  }
}

function inspectRegistrationCertificate(header: Record<string, unknown>, payload: Record<string, unknown>): Inspection {
  // Without the access certificate, compare the subject with itself, which leaves out that check
  const normalized = normalizeWRPRCPayload(payload)
  const subject = isRecord(normalized)
    ? isRecord(normalized.intermediary)
      ? normalized.intermediary.sub
      : normalized.sub
    : undefined
  const result = validateWRPRC(header, payload, typeof subject === 'string' ? subject : '')

  return {
    kind: 'registration-certificate',
    title: 'Registration certificate (ETSI TS 119 475)',
    checks: ['ETSI TS 119 475 header and payload'],
    notes: [
      'The subject is not compared with the access certificate of the relying party',
      'The JAdES signature is not verified',
    ],
    value: { header, payload },
    findings: result.findings,
  }
}

// Status values of draft-ietf-oauth-status-list-16 Section 7.1
function statusName(status: number): string {
  const hex = `0x${status.toString(16).padStart(2, '0')}`
  if (status === 0) return `Valid (${hex})`
  if (status === 1) return `Invalid (${hex})`
  if (status === 2) return `Suspended (${hex})`
  if (status === 3 || (status >= 0x0c && status <= 0x0f)) return `Application specific (${hex})`
  return `Reserved (${hex})`
}

function inspectStatusList(header: Record<string, unknown>, payload: Record<string, unknown>): Inspection {
  const { findings, statusList } = validateStatusListJwt(header, payload)
  const inspection: Inspection = {
    kind: 'status-list',
    title: 'Token Status List (JWT)',
    checks: ['draft-ietf-oauth-status-list-16 header and claims'],
    notes: ['The signature is not verified', 'sub is not compared with the uri of a referenced token'],
    value: { header, payload },
    findings,
  }
  if (!statusList) return inspection

  const total = statusList.totalStatuses
  const counts = new Map<number, number>()
  for (const status of statusList.statusList) counts.set(status, (counts.get(status) ?? 0) + 1)
  inspection.facts = [
    // The compressed list does not keep its length, so it is padded to whole bytes
    ['Entries', `${total.toLocaleString('en')} of ${statusList.getBitsPerStatus()} bits, padded to whole bytes`],
    [
      'Statuses',
      [...counts]
        .sort(([a], [b]) => a - b)
        .map(([status, count]) => `${statusName(status)}: ${count.toLocaleString('en')}`)
        .join(', '),
    ],
  ]
  inspection.lookup = {
    label: 'Status at index',
    placeholder: `0 to ${total - 1}`,
    find: (input) => {
      const index = Number(input)
      if (input.trim() === '' || !Number.isInteger(index) || index < 0 || index >= total) {
        return `The index must be a whole number from 0 to ${total - 1}`
      }
      return statusName(statusList.getStatus(index))
    },
  }
  return inspection
}

function inspectAccessCertificate(input: string | Uint8Array): Inspection {
  let accessCertificate: ReturnType<typeof parseAccessCertificate>
  try {
    accessCertificate = parseAccessCertificate(input)
  } catch (error) {
    throw new InspectionError(`This is not a parsable X.509 certificate: ${errorMessage(error)}`)
  }

  return {
    kind: 'access-certificate',
    title:
      accessCertificate.policies.length > 0
        ? 'Access certificate (ETSI TS 119 411-8)'
        : 'X.509 certificate, checked as an access certificate',
    checks: ['ETSI TS 119 411-8 certificate profile'],
    notes: ['The signature, the chain and the revocation status are not checked'],
    value: accessCertificate,
    findings: validateAccessCertificate(accessCertificate).findings,
  }
}
