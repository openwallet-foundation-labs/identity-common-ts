/**
 * LoTE Validator
 *
 * Runtime validation for ETSI TS 119 602 LoTE documents using Zod schemas.
 */

import z from 'zod'
import { LoTEException } from './lote-exception'
import {
  EUEAAProvidersListSchema,
  EUPIDProvidersListSchema,
  EUPubEAAProvidersListSchema,
  EUWalletProvidersListSchema,
  EUWRPACProvidersListSchema,
  EUWRPRCProvidersListSchema,
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

const profileToSchemaMap: Record<LoTEProfile, z.ZodType> = {
  [LoTEProfile.EUPIDProvidersList]: EUPIDProvidersListSchema,
  [LoTEProfile.EUWalletProvidersList]: EUWalletProvidersListSchema,
  [LoTEProfile.EUWRPACProvidersList]: EUWRPACProvidersListSchema,
  [LoTEProfile.EUWRPRCProvidersList]: EUWRPRCProvidersListSchema,
  [LoTEProfile.EUEAAProvidersList]: EUEAAProvidersListSchema,
  [LoTEProfile.EUPubEAAProvidersList]: EUPubEAAProvidersListSchema,
  [LoTEProfile.mDLProvidersList]: mDLProvidersListSchema,
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
  const schema = z.union(profiles.map((p) => profileToSchemaMap[p]))
  const result = schema.safeParse(loteDocument)

  if (result.success) {
    return { valid: true, errors: [] }
  }

  return {
    valid: false,
    errors: [
      {
        path: 'LoTEType',
        message: `Document does not match any of the specified profiles: ${profiles.join(', ')}`,
      },
      ...result.error.issues.flatMap((issue) => {
        if (issue.code === 'invalid_union') {
          // `issue.errors` holds one array of issues per union branch, in the same order as `profiles`
          return issue.errors.flatMap((branchIssues, index) =>
            branchIssues.map((branchIssue) => ({
              path: branchIssue.path.join('.'),
              message: `Profile ${profiles[index]}: ${branchIssue.message}`,
            }))
          )
        }

        return [{ path: issue.path.join('.'), message: issue.message }]
      }),
    ],
  }
}
