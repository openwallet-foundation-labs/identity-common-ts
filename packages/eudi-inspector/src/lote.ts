import { LOTE_VALIDATION_CODES, LoTEProfile, validateLoTE, validateLoTEProfile } from '@owf/eudi-lote'
import { decodeJwt, type Finding } from '@owf/identity-common'
import { type DocumentInput, errorMessage, isRecord, JWS, toText, withPathPrefix } from './input'
import { type Inspection, InspectionError } from './inspection'
import { jwsSignatureCheck } from './signature'

export interface LoTEOptions {
  /** The key or certificates of the signer of a LoTE JWS */
  key?: string
}

const findingKey = (finding: Finding) => `${finding.code}|${finding.path.join('.')}`

/** Parse an ETSI TS 119 602 List of Trusted Entities, as JSON or JWS, and check it and its profile */
export function inspectLoTE(input: DocumentInput, options: LoTEOptions = {}): Inspection {
  const text = toText(input)
  if (!text) throw new InspectionError('There is nothing to inspect')

  let document: unknown
  let header: Record<string, unknown> | undefined
  if (JWS.test(text)) {
    try {
      ;({ header, payload: document } = decodeJwt<Record<string, unknown>, Record<string, unknown>>(text))
    } catch (error) {
      throw new InspectionError(`This looks like a JWS, but it cannot be decoded: ${errorMessage(error)}`)
    }
  } else {
    try {
      document = JSON.parse(text)
    } catch (error) {
      throw new InspectionError(`A LoTE is JSON or a JWS, and this is neither: ${errorMessage(error)}`)
    }
  }
  if (!isRecord(document) || !('LoTE' in document)) {
    throw new InspectionError('This is not a LoTE document, as it has no LoTE property')
  }

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
  if (!header) notes.push('Unsigned JSON, so there is no signature to verify')

  return {
    kind: 'lote',
    title: 'List of Trusted Entities (ETSI TS 119 602)',
    checks,
    notes,
    value: header ? { header, payload: document } : document,
    findings: header ? withPathPrefix('payload', findings) : findings,
    signatures: header ? [jwsSignatureCheck(text, header, options.key)] : undefined,
  }
}
