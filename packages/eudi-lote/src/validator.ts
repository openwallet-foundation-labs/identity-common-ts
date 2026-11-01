/**
 * LoTE Validator
 *
 * Runtime validation for ETSI TS 119 602 LoTE documents using Zod schemas.
 */

import {
  type ValidationResult as CommonValidationResult,
  type SchemaIssueCode,
  schemaIssueToValidationIssue,
  toValidationResult,
  type ValidationIssueOf,
  validationErrors,
} from '@owf/identity-common'
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

/** An issue of a LoTE validation, with a zod issue code for schema issues */
export type LoTEValidationIssue = ValidationIssueOf<LoTEValidationCode | SchemaIssueCode>

/** Validation result, with all issues of the document */
export type ValidationResult = CommonValidationResult<LoTEValidationIssue>

const fromZodIssue = (issue: z.ZodError['issues'][number]): LoTEValidationIssue =>
  schemaIssueToValidationIssue(issue) as LoTEValidationIssue

/**
 * Validate a LoTE document against ETSI TS 119 602 schema
 *
 * @param loteDocument - The LoTE document to validate
 * @returns Validation result with the issues of the document
 *
 * @example
 * ```typescript
 * const result = validateLoTE(myLoTE);
 * if (!result.valid) {
 *   console.error('Validation issues:', result.issues);
 * }
 * ```
 */
export function validateLoTE(loteDocument: unknown): ValidationResult {
  const result = LoTEDocumentSchema.safeParse(loteDocument)
  return toValidationResult(result.success ? [] : result.error.issues.map(fromZodIssue))
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
    const errorMessages = validationErrors(result)
      .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
      .join('\n')
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
 * @returns Validation result with the issues of the document
 */
export function validateLoTEProfile(loteDocument: unknown, profile: LoTEProfile | LoTEProfile[]): ValidationResult {
  const profiles = Array.isArray(profile) ? profile : [profile]
  const documentLoTEType = getDocumentLoTEType(loteDocument)

  // LoTEType is unique per profile, so at most one requested profile can match.
  const matchedProfile = profiles.find((p) => profileConfig[p].loTEType === documentLoTEType)

  if (matchedProfile) {
    const result = profileConfig[matchedProfile].schema.safeParse(loteDocument)

    return toValidationResult(
      result.success
        ? []
        : result.error.issues.map((issue) => ({
            ...fromZodIssue(issue),
            message: `Profile ${matchedProfile}: ${issue.message}`,
          }))
    )
  }

  // No requested profile matches the document's LoTEType.
  return toValidationResult(
    profiles.map(
      (p): LoTEValidationIssue => ({
        severity: 'error',
        code: LOTE_VALIDATION_CODES.UNEXPECTED_LOTE_TYPE,
        path: ['LoTE', 'ListAndSchemeInformation', 'LoTEType'],
        message: `Profile ${p}: LoTEType must be ${profileConfig[p].loTEType}`,
      })
    )
  )
}
