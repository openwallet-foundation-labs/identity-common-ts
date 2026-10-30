/**
 * LoTE Validator
 *
 * Runtime validation for ETSI TS 119 602 LoTE documents using Zod schemas.
 */

import { type Finding, hasErrorFindings, schemaIssueToFinding } from '@owf/identity-common'
import type z from 'zod'
import { LoTEException } from './lote-exception'
import {
  EUEAAProvidersListSchema,
  EUPIDProvidersListSchema,
  EUPubEAAProvidersListSchema,
  EUWalletProvidersListSchema,
  EUWRPACProvidersListSchema,
  EUWRPRCProvidersListSchema,
  LOTE_TYPES,
  mDLProvidersListSchema,
} from './profiles'
import { LoTEDocumentSchema } from './schemas'
import type { LoTEDocument } from './types'

/**
 * Codes for the profile checks, beyond schema parsing, whose issues carry the zod issue
 * code instead.
 */
export const LOTE_VALIDATION_CODES = {
  /** `LoTEType` is not the one of any of the requested profiles */
  UNEXPECTED_LOTE_TYPE: 'unexpected_lote_type',
} as const

/** A profile validation code emitted by this validator */
export type LoTEValidationCode = (typeof LOTE_VALIDATION_CODES)[keyof typeof LOTE_VALIDATION_CODES]

/** A finding of a LoTE validation, with a zod issue code for schema issues */
export type LoTEFinding = Finding<LoTEValidationCode | (string & {})>

/**
 * Validation error detail
 */
export interface ValidationError {
  /** Path to the invalid field */
  path: string
  /** Error message */
  message: string
}

/**
 * Validation result
 */
export interface ValidationResult {
  /** Whether the LoTE document is valid */
  valid: boolean
  /** List of validation errors (if invalid) */
  errors: ValidationError[]
  /**
   * The problems as findings, with a code and with array indices as numbers in the path.
   * Unlike `errors`, they carry no summary entry for the document as a whole.
   */
  findings: LoTEFinding[]
}

const toValidationError = (finding: LoTEFinding): ValidationError => ({
  path: finding.path.join('.'),
  message: finding.message,
})

/**
 * Validate a LoTE document against ETSI TS 119 602 schema
 *
 * @param loteDocument - The LoTE document to validate
 * @returns Validation result with errors if invalid
 *
 * @example
 * ```typescript
 * const result = validateLoTE(myLoTE);
 * if (!result.valid) {
 *   console.error('Validation errors:', result.errors);
 * }
 * ```
 */
export function validateLoTE(loteDocument: unknown): ValidationResult {
  const result = LoTEDocumentSchema.safeParse(loteDocument)
  const findings = result.success ? [] : result.error.issues.map((issue) => schemaIssueToFinding(issue))

  return { valid: !hasErrorFindings(findings), errors: findings.map(toValidationError), findings }
}

/**
 * Assert that a LoTE document is valid, throwing if not
 *
 * @param loteDocument - The LoTE document to validate
 * @throws Error if validation fails
 */
export function assertValidLoTE(loteDocument: unknown): asserts loteDocument is LoTEDocument {
  const result = validateLoTE(loteDocument)
  if (!result.valid) {
    const errorMessages = result.errors.map((e) => `${e.path}: ${e.message}`).join('\n')
    throw new LoTEException(`Invalid LoTE document:\n${errorMessages}`)
  }
}

/**
 * Supported LoTE profiles for validation
 */
export enum LoTEProfile {
  EUPIDProvidersList = 'EUPIDProvidersList',
  EUWalletProvidersList = 'EUWalletProvidersList',
  EUWRPACProvidersList = 'EUWRPACProvidersList',
  EUWRPRCProvidersList = 'EUWRPRCProvidersList',
  EUEAAProvidersList = 'EUEAAProvidersList',
  EUPubEAAProvidersList = 'EUPubEAAProvidersList',
  mDLProvidersList = 'mDLProvidersList',
}

const profileConfig: Record<LoTEProfile, { loTEType: string; schema: z.ZodType }> = {
  [LoTEProfile.EUPIDProvidersList]: { loTEType: LOTE_TYPES.EUPIDProvidersList, schema: EUPIDProvidersListSchema },
  [LoTEProfile.EUWalletProvidersList]: {
    loTEType: LOTE_TYPES.EUWalletProvidersList,
    schema: EUWalletProvidersListSchema,
  },
  [LoTEProfile.EUWRPACProvidersList]: { loTEType: LOTE_TYPES.EUWRPACProvidersList, schema: EUWRPACProvidersListSchema },
  [LoTEProfile.EUWRPRCProvidersList]: { loTEType: LOTE_TYPES.EUWRPRCProvidersList, schema: EUWRPRCProvidersListSchema },
  [LoTEProfile.EUEAAProvidersList]: { loTEType: LOTE_TYPES.EUEAAProvidersList, schema: EUEAAProvidersListSchema },
  [LoTEProfile.EUPubEAAProvidersList]: {
    loTEType: LOTE_TYPES.EUPubEAAProvidersList,
    schema: EUPubEAAProvidersListSchema,
  },
  [LoTEProfile.mDLProvidersList]: { loTEType: LOTE_TYPES.mDLProvidersList, schema: mDLProvidersListSchema },
}

function getDocumentLoTEType(loteDocument: unknown): string | undefined {
  try {
    const type = (loteDocument as { LoTE?: { ListAndSchemeInformation?: { LoTEType?: unknown } } } | null | undefined)
      ?.LoTE?.ListAndSchemeInformation?.LoTEType
    return typeof type === 'string' ? type : undefined
  } catch {
    return undefined
  }
}

/**
 * Validate a LoTE document against one or more given profiles. Validation
 * succeeds if the document matches one of the specified profiles
 *
 * @param loteDocument - The LoTE document to validate
 * @param profile - The profile(s) to validate against
 * @returns Validation result with errors if invalid
 */
export function validateLoTEProfile(loteDocument: unknown, profile: LoTEProfile | LoTEProfile[]): ValidationResult {
  const profiles = Array.isArray(profile) ? profile : [profile]
  const documentLoTEType = getDocumentLoTEType(loteDocument)

  // LoTEType is unique per profile, so at most one requested profile can match.
  const matchedProfile = profiles.find((p) => profileConfig[p].loTEType === documentLoTEType)

  if (matchedProfile) {
    const result = profileConfig[matchedProfile].schema.safeParse(loteDocument)

    if (result.success) {
      return { valid: true, errors: [], findings: [] }
    }

    const findings = result.error.issues.map((issue) => ({
      ...schemaIssueToFinding(issue),
      message: `Profile ${matchedProfile}: ${issue.message}`,
    }))
    return {
      valid: false,
      errors: [
        { path: 'LoTEType', message: `Document does not match profile ${matchedProfile}` },
        ...findings.map(toValidationError),
      ],
      findings,
    }
  }

  // No requested profile matches the document's LoTEType.
  const findings: LoTEFinding[] = profiles.map((p) => ({
    severity: 'error',
    code: LOTE_VALIDATION_CODES.UNEXPECTED_LOTE_TYPE,
    path: ['LoTE', 'ListAndSchemeInformation', 'LoTEType'],
    message: `Profile ${p}: LoTEType must be ${profileConfig[p].loTEType}`,
  }))
  return {
    valid: false,
    errors: [
      {
        path: 'LoTEType',
        message: `Document does not match any of the specified profiles: ${profiles.join(', ')}`,
      },
      ...findings.map(toValidationError),
    ],
    findings,
  }
}
