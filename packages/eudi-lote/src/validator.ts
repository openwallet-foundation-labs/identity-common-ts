/**
 * LoTE Validator
 *
 * Runtime validation for ETSI TS 119 602 LoTE documents using Zod schemas.
 */

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
}

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

  if (result.success) {
    return { valid: true, errors: [] }
  }

  const errors: ValidationError[] = result.error.issues.map((issue) => ({
    path: issue.path.join('.'),
    message: issue.message,
  }))

  return { valid: false, errors }
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
      return { valid: true, errors: [] }
    }

    return {
      valid: false,
      errors: [
        { path: 'LoTEType', message: `Document does not match profile ${matchedProfile}` },
        ...result.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: `Profile ${matchedProfile}: ${issue.message}`,
        })),
      ],
    }
  }

  // No requested profile matches the document's LoTEType.
  return {
    valid: false,
    errors: [
      {
        path: 'LoTEType',
        message: `Document does not match any of the specified profiles: ${profiles.join(', ')}`,
      },
      ...profiles.map((p) => ({
        path: 'LoTE.ListAndSchemeInformation.LoTEType',
        message: `Profile ${p}: LoTEType must be ${profileConfig[p].loTEType}`,
      })),
    ],
  }
}
