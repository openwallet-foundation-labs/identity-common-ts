import {
  getAccessCertificateSubjectIdentifier,
  parseAccessCertificate,
  validateAccessCertificate,
} from '@owf/eudi-access-certificate'
import { normalizeWRPRCPayload, validateWRPRC } from '@owf/eudi-registration-certificate'
import { decodeJwt, type Finding } from '@owf/identity-common'
import { type DocumentInput, errorMessage, isRecord, JWS, toText, typOf, withPathPrefix } from './input'
import { type Inspection, InspectionError } from './inspection'
import { jwsSignatureCheck } from './signature'

export interface RegistrationCertificateOptions {
  /** The access certificate of the relying party, as PEM, base64 or hex */
  accessCertificate?: string
  /** The key or certificates of the signer */
  key?: string
}

/** The subject the registration certificate is for: the one of the intermediary, if there is one */
export function registeredSubject(payload: unknown): string | undefined {
  const normalized = normalizeWRPRCPayload(payload)
  if (!isRecord(normalized)) return undefined
  const sub = isRecord(normalized.intermediary) ? normalized.intermediary.sub : normalized.sub
  return typeof sub === 'string' ? sub : undefined
}

/**
 * Parse an ETSI TS 119 475 registration certificate, check it and, with the access
 * certificate of the relying party, that it is for the subject of that certificate.
 */
export function inspectRegistrationCertificate(
  input: DocumentInput,
  options: RegistrationCertificateOptions = {}
): Inspection {
  const jws = toText(input)
  if (!jws) throw new InspectionError('There is nothing to inspect')
  if (!JWS.test(jws)) throw new InspectionError('A registration certificate is a JWT, and this is not one')
  let header: Record<string, unknown>
  let payload: Record<string, unknown>
  try {
    ;({ header, payload } = decodeJwt<Record<string, unknown>, Record<string, unknown>>(jws))
  } catch (error) {
    throw new InspectionError(`The JWT cannot be decoded: ${errorMessage(error)}`)
  }
  if (typOf(header) !== 'rc-wrp+jwt' && !('credentials' in payload) && !('entitlements' in payload)) {
    throw new InspectionError(
      `This JWT has the typ ${String(header.typ ?? '(none)')} and no registration claims, so it is not a registration certificate`
    )
  }

  const checks = ['ETSI TS 119 475 header and payload']
  const notes: string[] = []
  const value: Record<string, unknown> = { header, payload }
  const facts: [string, string][] = []

  // Without the access certificate, compare the subject with itself, which leaves out that check
  let subject = registeredSubject(payload) ?? ''
  const findings: Finding[] = []
  if (options.accessCertificate?.trim()) {
    let accessCertificate: ReturnType<typeof parseAccessCertificate>
    try {
      accessCertificate = parseAccessCertificate(options.accessCertificate.trim())
    } catch (error) {
      throw new InspectionError(`The access certificate cannot be parsed: ${errorMessage(error)}`)
    }
    const accessSubject = getAccessCertificateSubjectIdentifier(accessCertificate)
    if (accessSubject) {
      subject = accessSubject
      checks.push('Subject against the access certificate')
      facts.push(['Access certificate subject', accessSubject])
    } else {
      notes.push('The access certificate has no subject identifier to compare the subject with')
    }
    checks.push('ETSI TS 119 411-8 access certificate profile')
    value.access_certificate = accessCertificate
    findings.push(...withPathPrefix('access_certificate', validateAccessCertificate(accessCertificate).findings))
  } else {
    notes.push('The subject is not compared with the access certificate of the relying party: give it to do so')
  }
  findings.unshift(...validateWRPRC(header, payload, subject).findings)

  return {
    kind: 'registration-certificate',
    title: 'Registration certificate (ETSI TS 119 475)',
    checks,
    notes,
    value,
    findings,
    facts,
    signatures: [jwsSignatureCheck(jws, header, options.key)],
  }
}
