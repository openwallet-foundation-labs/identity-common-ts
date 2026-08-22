/** Structural baseline-profile checks from ETSI TS 119 182-1 V1.2.1 clause 6.3. */
import { base64urlDecode } from '@owf/identity-common'
import { JAdESProfile } from './constants'
import { ProtectedHeaderSchema, UnprotectedHeaderSchema } from './schemas'
import type { ProtectedHeaderParams, UnprotectedHeaderParams } from './types'

export interface ProfileValidationOptions {
  /** Validation data is embedded in containers this package cannot inspect (for example RFC 3161 tokens). */
  signatureValidationDataAvailable?: boolean
  /** Time-stamp validation data is embedded in the time-stamps themselves. */
  timestampValidationDataAvailable?: boolean
}

export interface ProfileValidationResult {
  valid: boolean
  missing?: string[]
}

type EtsiUItem = Record<string, unknown>

function decodeEtsiU(header?: UnprotectedHeaderParams): EtsiUItem[] {
  if (!header) return []
  return header.etsiU.flatMap((item) => {
    if (typeof item !== 'string') return [item as EtsiUItem]
    try {
      const decoded = JSON.parse(base64urlDecode(item))
      return typeof decoded === 'object' && decoded !== null ? [decoded as EtsiUItem] : []
    } catch {
      return []
    }
  })
}

function has(items: EtsiUItem[], name: string): boolean {
  return items.some((item) => name in item)
}

function addSchemaIssues(
  missing: string[],
  prefix: string,
  issues: ReadonlyArray<{ path: PropertyKey[]; message: string }>
): void {
  for (const issue of issues) missing.push(`${prefix}${issue.path.join('.')}: ${issue.message}`)
}

function checkBaselineTimestamp(container: unknown, path: string, missing: string[], exactlyOne = false): void {
  const tokens =
    typeof container === 'object' &&
    container !== null &&
    Array.isArray((container as { tstTokens?: unknown }).tstTokens)
      ? (container as { tstTokens: unknown[] }).tstTokens
      : []
  if (exactlyOne && tokens.length !== 1) missing.push(`${path} must contain exactly one RFC 3161 time-stamp token`)
  for (const token of tokens) {
    if (typeof token !== 'object' || token === null || Object.keys(token).length !== 1 || !('val' in token)) {
      missing.push(`${path} baseline time-stamps must be RFC 3161 tokens represented only by val`)
    }
  }
}

function validateBB(
  header: ProtectedHeaderParams,
  unprotectedHeader?: UnprotectedHeaderParams
): ProfileValidationResult {
  const missing: string[] = []
  const protectedResult = ProtectedHeaderSchema.safeParse(header)
  if (!protectedResult.success) addSchemaIssues(missing, 'protected.', protectedResult.error.issues)
  if (unprotectedHeader) {
    const unprotectedResult = UnprotectedHeaderSchema.safeParse(unprotectedHeader)
    if (!unprotectedResult.success) addSchemaIssues(missing, 'unprotected.', unprotectedResult.error.issues)
  }
  if (header.adoTst) checkBaselineTimestamp(header.adoTst, 'protected.adoTst', missing)
  const items = decodeEtsiU(unprotectedHeader)
  for (const item of items) {
    for (const key of ['sigTst', 'arcTst', 'sigRTst', 'rfsTst'] as const) {
      if (key in item) checkBaselineTimestamp(item[key], `etsiU.${key}`, missing, key === 'sigTst')
    }
  }
  if (has(items, 'sigPSt') && !header.sigPId?.digVal) {
    missing.push('etsiU.sigPSt requires protected sigPId with digVal')
  }
  for (const item of items) {
    for (const key of ['xRefs', 'axRefs'] as const) {
      const references = item[key]
      if (
        Array.isArray(references) &&
        references.some((reference) => typeof reference === 'object' && reference && 'x5u' in reference)
      ) {
        missing.push(`etsiU.${key} must not contain x5u`)
      }
    }
  }
  if ((has(items, 'axRefs') || has(items, 'arRefs')) && !header.srAts?.certified && !header.srAts?.signedAssertions) {
    missing.push('axRefs and arRefs require a certified attribute or signed assertion in srAts')
  }
  return { valid: missing.length === 0, missing: missing.length ? missing : undefined }
}

function validateBT(
  header: ProtectedHeaderParams,
  unprotectedHeader?: UnprotectedHeaderParams
): ProfileValidationResult {
  const missing = [...(validateBB(header, unprotectedHeader).missing ?? [])]
  const items = decodeEtsiU(unprotectedHeader)
  const timestamps = items.flatMap((item) => ('sigTst' in item ? [item.sigTst] : []))
  if (timestamps.length === 0) missing.push('etsiU.sigTst is required')
  return { valid: missing.length === 0, missing: missing.length ? missing : undefined }
}

const REFERENCE_COMPONENTS = ['xRefs', 'rRefs', 'axRefs', 'arRefs', 'sigRTst', 'rfsTst'] as const

function validateBLT(
  header: ProtectedHeaderParams,
  unprotectedHeader?: UnprotectedHeaderParams,
  options: ProfileValidationOptions = {}
): ProfileValidationResult {
  const missing = [...(validateBT(header, unprotectedHeader).missing ?? [])]
  const items = decodeEtsiU(unprotectedHeader)
  for (const component of REFERENCE_COMPONENTS) {
    if (has(items, component)) missing.push(`etsiU.${component} is prohibited at B-LT and B-LTA levels`)
  }

  const valueContainers = items.flatMap((item) => {
    if ('anyValData' in item) return [item.anyValData]
    return [item]
  })
  const certificateValues =
    options.signatureValidationDataAvailable ||
    has(items, 'xVals') ||
    valueContainers.some((value) => typeof value === 'object' && value !== null && 'xVals' in value)
  const revocationValues =
    options.signatureValidationDataAvailable ||
    has(items, 'rVals') ||
    valueContainers.some((value) => typeof value === 'object' && value !== null && 'rVals' in value)
  if (!certificateValues) missing.push('Certificate validation values required for B-LT are not evidenced')
  if (!revocationValues) missing.push('Revocation validation values required for B-LT are not evidenced')

  const timestampData =
    options.timestampValidationDataAvailable ||
    items.some((item) => {
      const value = 'tstVD' in item ? item.tstVD : 'anyValData' in item ? item.anyValData : undefined
      return typeof value === 'object' && value !== null && 'xVals' in value && 'rVals' in value
    })
  if (!timestampData) missing.push('Validation data for electronic time-stamps is not evidenced')

  return { valid: missing.length === 0, missing: missing.length ? missing : undefined }
}

function validateBLTA(
  header: ProtectedHeaderParams,
  unprotectedHeader?: UnprotectedHeaderParams,
  options: ProfileValidationOptions = {}
): ProfileValidationResult {
  const missing = [...(validateBLT(header, unprotectedHeader, options).missing ?? [])]
  if (!has(decodeEtsiU(unprotectedHeader), 'arcTst')) missing.push('etsiU.arcTst is required')
  return { valid: missing.length === 0, missing: missing.length ? missing : undefined }
}

export function validateProfile(
  header: ProtectedHeaderParams,
  profile: JAdESProfile,
  unprotectedHeader?: UnprotectedHeaderParams,
  options: ProfileValidationOptions = {}
): ProfileValidationResult {
  switch (profile) {
    case JAdESProfile.B_B:
      return validateBB(header, unprotectedHeader)
    case JAdESProfile.B_T:
      return validateBT(header, unprotectedHeader)
    case JAdESProfile.B_LT:
      return validateBLT(header, unprotectedHeader, options)
    case JAdESProfile.B_LTA:
      return validateBLTA(header, unprotectedHeader, options)
  }
}

export function detectProfiles(
  header: ProtectedHeaderParams,
  unprotectedHeader?: UnprotectedHeaderParams,
  options: ProfileValidationOptions = {}
): JAdESProfile[] {
  return [JAdESProfile.B_LTA, JAdESProfile.B_LT, JAdESProfile.B_T, JAdESProfile.B_B].filter(
    (profile) => validateProfile(header, profile, unprotectedHeader, options).valid
  )
}
