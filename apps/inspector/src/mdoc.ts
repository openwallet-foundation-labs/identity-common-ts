import { CborStructure, DataItem, DateOnly, TypedMap } from '@owf/cose'
import { hasher } from '@owf/crypto'
import { compareBytes, type Finding, type FindingSeverity } from '@owf/identity-common'
import {
  cborDecode,
  DeviceResponse,
  type IssuerSigned,
  type IssuerSignedItem,
  IssuerSigned as IssuerSignedStructure,
  type MobileSecurityObject,
} from '@owf/mdoc'
import { parseCertificate } from '@owf/x509'
import { type Inspection, InspectionError } from './inspection'

/** Codes of the findings of an mdoc inspection */
export const MDOC_CODES = {
  /** The issuerAuth has no x5chain with the issuer certificate */
  MISSING_X5CHAIN: 'missing_x5chain',
  /** The issuer certificate cannot be parsed */
  INVALID_CERTIFICATE: 'invalid_certificate',
  /** The Mobile Security Object cannot be decoded */
  INVALID_MSO: 'invalid_mso',
  /** The docType of the document differs from the one of the MSO */
  DOCTYPE_MISMATCH: 'doctype_mismatch',
  /** validFrom is before signed, or validUntil is not after validFrom */
  INVALID_VALIDITY: 'invalid_validity',
  /** validFrom is in the future */
  NOT_YET_VALID: 'not_yet_valid',
  /** validUntil is in the past */
  EXPIRED: 'expired',
  /** The MSO was signed outside the validity period of the issuer certificate */
  SIGNED_OUTSIDE_CERTIFICATE_VALIDITY: 'signed_outside_certificate_validity',
  /** The MSO has no digests for a namespace of the document */
  MISSING_NAMESPACE_DIGESTS: 'missing_namespace_digests',
  /** A namespace holds the same element identifier twice */
  DUPLICATE_ELEMENT: 'duplicate_element',
  /** The MSO has no digest for the digestID of an element */
  MISSING_DIGEST: 'missing_digest',
  /** The digest of an element differs from the one in the MSO */
  DIGEST_MISMATCH: 'digest_mismatch',
  /** The status of the device response is not OK (0) */
  RESPONSE_STATUS: 'response_status',
  /** The device response reports documents it could not return */
  DOCUMENT_ERRORS: 'document_errors',
} as const

type MdocCode = (typeof MDOC_CODES)[keyof typeof MDOC_CODES]
type MdocFinding = Finding<MdocCode>
type Path = (string | number)[]

const C = MDOC_CODES

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const errorMessage = (error: unknown) => (error instanceof Error ? error.message : String(error))

/** Whether the bytes start with a CBOR map, or a map wrapped in tag 24 */
export const isCborMap = (bytes: Uint8Array) => (bytes[0] & 0xe0) === 0xa0 || (bytes[0] === 0xd8 && bytes[1] === 0x18)

/** The decoded CBOR as plain objects, arrays and leaves, for the document tree */
export function toPlain(value: unknown): unknown {
  try {
    if (value instanceof CborStructure) return toPlain(value.decodedStructure)
    if (value instanceof TypedMap) return toPlain(value.toMap())
    if (value instanceof DataItem) return toPlain(value.data)
  } catch (error) {
    return `(cannot be decoded: ${errorMessage(error)})`
  }
  if (value instanceof DateOnly) return value.toISOString()
  if (value instanceof Uint8Array || value instanceof Date) return value
  if (value instanceof Map) return Object.fromEntries([...value].map(([key, member]) => [String(key), toPlain(member)]))
  if (Array.isArray(value)) return value.map(toPlain)
  // A CBOR tag the decoder does not know
  if (isRecord(value) && typeof value.tag === 'number' && 'value' in value && Object.keys(value).length === 2) {
    return { tag: value.tag, value: toPlain(value.value) }
  }
  if (isRecord(value)) return Object.fromEntries(Object.entries(value).map(([key, member]) => [key, toPlain(member)]))
  return value
}

const withPathPrefix = <T extends Finding>(prefix: Path, findings: T[]): T[] =>
  findings.map((finding) => ({ ...finding, path: [...prefix, ...finding.path] }))

interface IssuerSignedCheck {
  value: Record<string, unknown>
  findings: MdocFinding[]
  facts: [string, string][]
}

/**
 * Check an IssuerSigned without its signature: the MSO, its validity window, the issuer
 * certificate it was signed within, and the digest of every element.
 */
function checkIssuerSigned(issuerSigned: IssuerSigned, documentDocType?: string): IssuerSignedCheck {
  const findings: MdocFinding[] = []
  const add = (severity: FindingSeverity, code: MdocCode, path: Path, message: string) =>
    findings.push({ severity, code, path, message })
  const facts: [string, string][] = []
  const value: Record<string, unknown> = {}
  const now = new Date()
  const { issuerAuth } = issuerSigned

  // Issuer certificate
  let certificate: ReturnType<typeof parseCertificate> | undefined
  const x5chain = issuerAuth.x5chain
  let algorithm: string | undefined
  try {
    algorithm = issuerAuth.jwaAlgorithm
  } catch {
    algorithm = undefined
  }
  if (!x5chain?.length) {
    add('error', C.MISSING_X5CHAIN, ['issuerAuth', 'x5chain'], 'issuerAuth has no x5chain with the issuer certificate')
  } else {
    try {
      certificate = parseCertificate(x5chain[0])
    } catch (error) {
      add('error', C.INVALID_CERTIFICATE, ['issuerAuth', 'x5chain'], errorMessage(error))
    }
  }
  value.issuerAuth = {
    algorithm,
    x5chain: x5chain?.length ?? 0,
    ...(certificate
      ? {
          certificate: {
            subject: certificate.subject,
            issuer: certificate.issuer,
            serialNumber: certificate.serialNumber,
            notBefore: certificate.notBefore,
            notAfter: certificate.notAfter,
          },
        }
      : {}),
  }
  if (certificate) facts.push(['Issuer', certificate.subject.commonName ?? certificate.subject.organizationName ?? '-'])

  // Mobile Security Object
  let mso: MobileSecurityObject | undefined
  try {
    mso = issuerAuth.mobileSecurityObject
  } catch (error) {
    add('error', C.INVALID_MSO, ['issuerAuth'], `The Mobile Security Object cannot be decoded: ${errorMessage(error)}`)
  }

  const namespaces: Map<string, IssuerSignedItem[]> = issuerSigned.issuerNamespaces?.issuerNamespaces ?? new Map()
  value.namespaces = Object.fromEntries(
    [...namespaces].map(([namespace, items]) => [
      namespace,
      items.map((item) => ({
        elementIdentifier: item.elementIdentifier,
        elementValue: toPlain(item.elementValue),
        digestID: item.digestId,
        random: item.random,
      })),
    ])
  )
  const elements = [...namespaces.values()].reduce((count, items) => count + items.length, 0)

  if (mso) {
    const { validityInfo } = mso
    value.mso = {
      version: mso.version,
      docType: mso.docType,
      digestAlgorithm: mso.digestAlgorithm,
      validityInfo: {
        signed: validityInfo.signed,
        validFrom: validityInfo.validFrom,
        validUntil: validityInfo.validUntil,
        ...(validityInfo.expectedUpdate ? { expectedUpdate: validityInfo.expectedUpdate } : {}),
      },
      valueDigests: toPlain(mso.valueDigests.valueDigests),
      deviceKeyInfo: toPlain(mso.deviceKeyInfo),
      ...(mso.status ? { status: toPlain(mso.status) } : {}),
    }
    facts.unshift(['Document type', mso.docType])
    facts.push(
      ['Valid', `${validityInfo.validFrom.toISOString()} to ${validityInfo.validUntil.toISOString()}`],
      ['Elements', `${elements} in ${namespaces.size} namespaces, digests with ${mso.digestAlgorithm}`]
    )

    if (documentDocType !== undefined && documentDocType !== mso.docType) {
      add('error', C.DOCTYPE_MISMATCH, ['mso', 'docType'], `The document has the docType ${documentDocType}`)
    }

    // Validity window
    const validity = ['mso', 'validityInfo']
    if (validityInfo.validFrom < validityInfo.signed) {
      add('error', C.INVALID_VALIDITY, [...validity, 'validFrom'], 'validFrom must not be before signed')
    }
    if (validityInfo.validUntil <= validityInfo.validFrom) {
      add('error', C.INVALID_VALIDITY, [...validity, 'validUntil'], 'validUntil must be after validFrom')
    }
    if (!validityInfo.isValidFromBeforeNow(now)) {
      add('error', C.NOT_YET_VALID, [...validity, 'validFrom'], 'The MSO is not valid yet')
    }
    if (!validityInfo.isValidUntilAfterNow(now)) {
      add(
        'error',
        C.EXPIRED,
        [...validity, 'validUntil'],
        `The MSO expired at ${validityInfo.validUntil.toISOString()}`
      )
    }
    if (certificate && (validityInfo.signed < certificate.notBefore || validityInfo.signed > certificate.notAfter)) {
      add(
        'error',
        C.SIGNED_OUTSIDE_CERTIFICATE_VALIDITY,
        [...validity, 'signed'],
        'The MSO was signed outside the validity period of the issuer certificate'
      )
    }

    // Value digests: the digest of IssuerSignedItemBytes, the item as received in tag 24
    for (const [namespace, items] of namespaces) {
      const digests = mso.valueDigests.valueDigests.get(namespace)
      if (!digests) {
        add(
          'error',
          C.MISSING_NAMESPACE_DIGESTS,
          ['namespaces', namespace],
          'The MSO has no digests for this namespace'
        )
        continue
      }
      const identifiers = new Set<string>()
      items.forEach((item, index) => {
        const path = ['namespaces', namespace, index]
        if (identifiers.has(item.elementIdentifier)) {
          add('error', C.DUPLICATE_ELEMENT, path, `${item.elementIdentifier} appears more than once in ${namespace}`)
        }
        identifiers.add(item.elementIdentifier)

        const expected = digests.get(item.digestId)
        if (!expected) {
          add(
            'error',
            C.MISSING_DIGEST,
            [...path, 'digestID'],
            `The MSO has no digest with the digestID ${item.digestId}`
          )
          return
        }
        const bytes = item.encode({ asDataItem: true })
        const digest = hasher(bytes.slice().buffer, mso.digestAlgorithm)
        if (compareBytes(digest, expected) !== true) {
          add(
            'error',
            C.DIGEST_MISMATCH,
            path,
            `The ${mso.digestAlgorithm} digest of ${item.elementIdentifier} differs from the digest in the MSO`
          )
        }
      })
    }
  }

  return { value, findings, facts }
}

const NOTES = ['The issuer signature and certificate chain are not verified', 'The status is not looked up']

/**
 * Decode an mdoc, as an IssuerSigned of OpenID4VCI or a DeviceResponse of OpenID4VP or
 * ISO/IEC 18013-5, and check it without verifying signatures.
 */
export function inspectMdoc(bytes: Uint8Array): Inspection {
  let decoded: unknown
  try {
    decoded = cborDecode(bytes)
  } catch (error) {
    throw new InspectionError(`This is not valid CBOR: ${errorMessage(error)}`)
  }
  const keys = decoded instanceof Map ? new Set([...decoded.keys()]) : new Set()

  if (keys.has('issuerAuth')) {
    let issuerSigned: IssuerSigned
    try {
      issuerSigned = IssuerSignedStructure.decode(bytes)
    } catch (error) {
      throw new InspectionError(`This is not a valid mdoc IssuerSigned: ${errorMessage(error)}`)
    }
    const { value, findings, facts } = checkIssuerSigned(issuerSigned)
    return {
      kind: 'mdoc',
      title: 'mdoc IssuerSigned (ISO/IEC 18013-5)',
      checks: ['Mobile Security Object, validity and value digests'],
      notes: NOTES,
      value,
      findings,
      facts,
    }
  }

  if (keys.has('version') && keys.has('status')) {
    let response: DeviceResponse
    try {
      response = DeviceResponse.decode(bytes)
    } catch (error) {
      throw new InspectionError(`This is not a valid mdoc DeviceResponse: ${errorMessage(error)}`)
    }
    const findings: MdocFinding[] = []
    if (response.status !== 0) {
      findings.push({
        severity: 'warning',
        code: C.RESPONSE_STATUS,
        path: ['status'],
        message: `The status is ${response.status}, not OK (0)`,
      })
    }
    if (response.documentErrors?.length) {
      findings.push({
        severity: 'warning',
        code: C.DOCUMENT_ERRORS,
        path: ['documentErrors'],
        message: 'The device response reports documents it could not return',
      })
    }
    const documents = (response.documents ?? []).map((document, index) => {
      const check = checkIssuerSigned(document.issuerSigned, document.docType)
      findings.push(...withPathPrefix(['documents', index, 'issuerSigned'], check.findings))
      return { docType: document.docType, issuerSigned: check.value, deviceSigned: toPlain(document.deviceSigned) }
    })

    return {
      kind: 'mdoc',
      title: 'mdoc DeviceResponse (ISO/IEC 18013-5)',
      checks: ['Mobile Security Object, validity and value digests of each document'],
      notes: [...NOTES, 'The device signature or MAC is not verified, as it needs the session transcript'],
      value: {
        version: response.version,
        status: response.status,
        documents,
        ...(response.documentErrors ? { documentErrors: toPlain(response.documentErrors) } : {}),
      },
      findings,
      facts: [
        ['Documents', documents.length > 0 ? documents.map((document) => document.docType).join(', ') : 'None'],
        ['Version', response.version],
      ],
    }
  }

  throw new InspectionError('This CBOR is neither an mdoc IssuerSigned nor a DeviceResponse')
}
