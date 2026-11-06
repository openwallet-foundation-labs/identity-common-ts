/** Structural baseline-profile checks from ETSI TS 119 182-1 V1.2.1 clause 6.3. */
import {
  base64urlDecodeJson,
  parseWithSchema,
  prefixIssuePaths,
  type SchemaValidationCode,
  ValidationIssues,
} from '@owf/identity-common'
import { JadesProfile } from './constants'
import { zProtectedHeader, zUnprotectedHeader } from './schemas'
import type { ProtectedHeaderParams, UnprotectedHeaderParams } from './types'
import { JADES_VALIDATION_CODES, type JadesValidationCode, type JadesValidationResult } from './validation'

export interface ProfileValidationOptions {
  /** Validation data is embedded in containers this package cannot inspect (for example RFC 3161 tokens). */
  signatureValidationDataAvailable?: boolean
  /** Time-stamp validation data is embedded in the time-stamps themselves. */
  timestampValidationDataAvailable?: boolean
}

/**
 * The result of a profile validation. Issue paths start with `protected` or `header`, the members of a JWS JSON
 * serialization that hold the protected and the unprotected header.
 */
export type ProfileValidationResult = JadesValidationResult

type EtsiUItem = Record<string, unknown>
type Issues = ValidationIssues<JadesValidationCode | SchemaValidationCode>

function decodeEtsiU(header?: UnprotectedHeaderParams): EtsiUItem[] {
  // Read before the header is validated, so `etsiU` and its items can be anything
  const etsiU: unknown = header?.etsiU
  if (!Array.isArray(etsiU)) return []
  return etsiU.flatMap((item) => {
    let decoded: unknown = item
    if (typeof item === 'string') {
      try {
        decoded = base64urlDecodeJson(item)
      } catch {
        return []
      }
    }
    return typeof decoded === 'object' && decoded !== null && !Array.isArray(decoded) ? [decoded as EtsiUItem] : []
  })
}

function has(items: EtsiUItem[], name: string): boolean {
  return items.some((item) => name in item)
}

function checkBaselineTimestamp(
  container: unknown,
  path: (string | number)[],
  issues: Issues,
  exactlyOne = false
): void {
  const tokens =
    typeof container === 'object' &&
    container !== null &&
    Array.isArray((container as { tstTokens?: unknown }).tstTokens)
      ? (container as { tstTokens: unknown[] }).tstTokens
      : []
  if (exactlyOne && tokens.length !== 1) {
    issues.add({
      code: JADES_VALIDATION_CODES.INVALID_TIMESTAMP,
      path,
      message: 'must contain exactly one RFC 3161 time-stamp token',
    })
  }
  for (const token of tokens) {
    if (typeof token !== 'object' || token === null || Object.keys(token).length !== 1 || !('val' in token)) {
      issues.add({
        code: JADES_VALIDATION_CODES.INVALID_TIMESTAMP,
        path,
        message: 'baseline time-stamps must be RFC 3161 tokens represented only by val',
      })
    }
  }
}

function validateBB(
  header: ProtectedHeaderParams,
  unprotectedHeader: UnprotectedHeaderParams | undefined,
  issues: Issues
) {
  const protectedResult = parseWithSchema(zProtectedHeader, header, { codes: JADES_VALIDATION_CODES })
  if (!protectedResult.success) issues.issues.push(...prefixIssuePaths('protected', protectedResult.issues))
  if (unprotectedHeader) {
    const unprotectedResult = parseWithSchema(zUnprotectedHeader, unprotectedHeader, { codes: JADES_VALIDATION_CODES })
    if (!unprotectedResult.success) issues.issues.push(...prefixIssuePaths('header', unprotectedResult.issues))
  }
  if (header.adoTst) checkBaselineTimestamp(header.adoTst, ['protected', 'adoTst'], issues)
  const items = decodeEtsiU(unprotectedHeader)
  items.forEach((item, index) => {
    for (const key of ['sigTst', 'arcTst', 'sigRTst', 'rfsTst'] as const) {
      if (key in item) checkBaselineTimestamp(item[key], ['header', 'etsiU', index, key], issues, key === 'sigTst')
    }
  })
  if (has(items, 'sigPSt') && !header.sigPId?.digVal) {
    issues.add({
      code: 'missing_value',
      path: ['protected', 'sigPId', 'digVal'],
      message: 'etsiU.sigPSt requires protected sigPId with digVal',
      context: { expected: 'string' },
    })
  }
  items.forEach((item, index) => {
    for (const key of ['xRefs', 'axRefs'] as const) {
      const references = item[key]
      if (
        Array.isArray(references) &&
        references.some((reference) => typeof reference === 'object' && reference && 'x5u' in reference)
      ) {
        issues.add({
          code: 'not_allowed',
          path: ['header', 'etsiU', index, key],
          message: `${key} must not contain x5u`,
        })
      }
    }
  })
  if ((has(items, 'axRefs') || has(items, 'arRefs')) && !header.srAts?.certified && !header.srAts?.signedAssertions) {
    issues.add({
      code: 'missing_value',
      path: ['protected', 'srAts'],
      message: 'axRefs and arRefs require a certified attribute or signed assertion in srAts',
      context: { expected: 'certified or signedAssertions' },
    })
  }
}

function validateBT(
  header: ProtectedHeaderParams,
  unprotectedHeader: UnprotectedHeaderParams | undefined,
  issues: Issues
) {
  validateBB(header, unprotectedHeader, issues)
  if (!has(decodeEtsiU(unprotectedHeader), 'sigTst')) {
    issues.add({
      code: 'missing_value',
      path: ['header', 'etsiU'],
      message: 'etsiU.sigTst is required',
      context: { expected: 'sigTst' },
    })
  }
}

const REFERENCE_COMPONENTS = ['xRefs', 'rRefs', 'axRefs', 'arRefs', 'sigRTst', 'rfsTst'] as const

function validateBLT(
  header: ProtectedHeaderParams,
  unprotectedHeader: UnprotectedHeaderParams | undefined,
  options: ProfileValidationOptions,
  issues: Issues
) {
  validateBT(header, unprotectedHeader, issues)
  const items = decodeEtsiU(unprotectedHeader)
  items.forEach((item, index) => {
    for (const component of REFERENCE_COMPONENTS.filter((component) => component in item)) {
      issues.add({
        code: 'not_allowed',
        path: ['header', 'etsiU', index, component],
        message: `etsiU.${component} is prohibited at B-LT and B-LTA levels`,
      })
    }
  })

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
  const missingValidationData = (message: string) =>
    issues.add({ code: JADES_VALIDATION_CODES.MISSING_VALIDATION_DATA, path: ['header', 'etsiU'], message })
  if (!certificateValues) missingValidationData('Certificate validation values required for B-LT are not evidenced')
  if (!revocationValues) missingValidationData('Revocation validation values required for B-LT are not evidenced')

  const timestampData =
    options.timestampValidationDataAvailable ||
    items.some((item) => {
      const value = 'tstVD' in item ? item.tstVD : 'anyValData' in item ? item.anyValData : undefined
      return typeof value === 'object' && value !== null && 'xVals' in value && 'rVals' in value
    })
  if (!timestampData) missingValidationData('Validation data for electronic time-stamps is not evidenced')
}

function validateBLTA(
  header: ProtectedHeaderParams,
  unprotectedHeader: UnprotectedHeaderParams | undefined,
  options: ProfileValidationOptions,
  issues: Issues
) {
  validateBLT(header, unprotectedHeader, options, issues)
  if (!has(decodeEtsiU(unprotectedHeader), 'arcTst')) {
    issues.add({
      code: 'missing_value',
      path: ['header', 'etsiU'],
      message: 'etsiU.arcTst is required',
      context: { expected: 'arcTst' },
    })
  }
}

/**
 * Validate the protected and unprotected header of a JAdES signature against clause 5 and a baseline profile of clause
 * 6.3, with an issue for each deviation.
 */
export function validateProfile(
  header: ProtectedHeaderParams,
  profile: JadesProfile,
  unprotectedHeader?: UnprotectedHeaderParams,
  options: ProfileValidationOptions = {}
): ProfileValidationResult {
  const issues: Issues = new ValidationIssues()
  switch (profile) {
    case JadesProfile.B_B:
      validateBB(header, unprotectedHeader, issues)
      break
    case JadesProfile.B_T:
      validateBT(header, unprotectedHeader, issues)
      break
    case JadesProfile.B_LT:
      validateBLT(header, unprotectedHeader, options, issues)
      break
    case JadesProfile.B_LTA:
      validateBLTA(header, unprotectedHeader, options, issues)
      break
  }
  return issues.result()
}

export function detectProfiles(
  header: ProtectedHeaderParams,
  unprotectedHeader?: UnprotectedHeaderParams,
  options: ProfileValidationOptions = {}
): JadesProfile[] {
  return [JadesProfile.B_LTA, JadesProfile.B_LT, JadesProfile.B_T, JadesProfile.B_B].filter(
    (profile) => validateProfile(header, profile, unprotectedHeader, options).valid
  )
}
