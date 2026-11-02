/**
 * LoTE Validator
 *
 * Runtime validation for ETSI TS 119 602 LoTE documents using Zod schemas.
 */

import {
  hasValidationErrors,
  type SchemaIssueCode,
  schemaIssueToValidationIssue,
  type ValidationIssueOf,
  validationErrors,
} from '@owf/identity-common'
import type z from 'zod'
import { LoTEException } from './lote-exception'
import {
  createProfileSchema,
  type LoTEProfileValidationOptions,
  type LoTEValidationMode,
  profileDefinitions,
} from './profiles'
import { CompatLoTEDocumentSchema, LoTEDocumentSchema } from './schemas'
import type { CompatLoTEDocument, LoTEDocument } from './types'

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

/**
 * Validation result, with all issues of the document. When valid, `lote` is the validated
 * document, typed by what was validated.
 */
export type ValidationResult<T = LoTEDocument> =
  | { valid: true; issues: LoTEValidationIssue[]; lote: T }
  | { valid: false; issues: LoTEValidationIssue[] }

/** The document `validateLoTE` accepts in a mode */
type ModeLoTEDocument<M extends LoTEValidationMode> = M extends 'compat' ? CompatLoTEDocument : LoTEDocument

const fromZodIssue = (issue: z.ZodError['issues'][number]): LoTEValidationIssue =>
  schemaIssueToValidationIssue(issue) as LoTEValidationIssue

/**
 * Validate a LoTE document against ETSI TS 119 602 schema
 *
 * @param loteDocument - The LoTE document to validate
 * @param options.mode - `compat` also accepts the `PolicyOrLegalNotice` of lists in use:
 * a `LoTELegalNotice` that is an array of localized URIs, and items with both keys. Defaults to `strict`.
 * @returns Validation result with the issues of the document, and when valid the document typed
 * as a `LoTEDocument` (strict) or `CompatLoTEDocument` (compat)
 *
 * @example
 * ```typescript
 * const result = validateLoTE(myLoTE);
 * if (!result.valid) {
 *   console.error('Validation issues:', result.issues);
 * }
 * ```
 */
export function validateLoTE<M extends LoTEValidationMode = 'strict'>(
  loteDocument: unknown,
  { mode }: { mode?: M } = {}
): ValidationResult<ModeLoTEDocument<M>> {
  const result = (mode === 'compat' ? CompatLoTEDocumentSchema : LoTEDocumentSchema).safeParse(loteDocument)
  const issues = result.success ? [] : result.error.issues.map(fromZodIssue)

  if (hasValidationErrors(issues)) {
    return { valid: false, issues }
  }

  // The input, not the parsed copy: that drops the keys the schema doesn't know
  return { valid: true, issues, lote: loteDocument as ModeLoTEDocument<M> }
}

/**
 * Assert that a LoTE document is valid, throwing if not
 *
 * @param loteDocument - The LoTE document to validate
 * @param options.mode - As in `validateLoTE`. Defaults to `strict`.
 * @throws Error if validation fails
 */
export function assertValidLoTE<M extends LoTEValidationMode = 'strict'>(
  loteDocument: unknown,
  options: { mode?: M } = {}
): asserts loteDocument is ModeLoTEDocument<M> {
  const result = validateLoTE(loteDocument, options)
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

/**
 * The document a profile accepts in a mode, with the profile's LoTEType, ServiceTypeIdentifier
 * and ServiceStatus values as literal types
 */
export type LoTEProfileDocument<P extends LoTEProfile, M extends LoTEValidationMode = 'strict'> = P extends LoTEProfile
  ? z.output<ReturnType<typeof createProfileSchema<(typeof profileDefinitions)[P], M>>>
  : never

/**
 * Validation result of `validateLoTEProfile`. When valid, `loteType` is the LoTEType of the
 * profile the document matches, and narrows `lote` to the `LoTEProfileDocument` of that profile.
 */
export type LoTEProfileValidationResult<P extends LoTEProfile, M extends LoTEValidationMode = 'strict'> =
  | (P extends LoTEProfile
      ? {
          valid: true
          issues: LoTEValidationIssue[]
          loteType: (typeof profileDefinitions)[P]['list']['loTEType']
          lote: LoTEProfileDocument<P, M>
        }
      : never)
  | { valid: false; issues: LoTEValidationIssue[] }

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
 * @param options.mode - `strict` (the default) validates the list exactly as the profile defines it.
 * `compat` also accepts the deviations of lists in use that don't change who is trusted: the
 * `PolicyOrLegalNotice` that `validateLoTE` accepts in compat mode, and on a PID Providers List
 * a `ServiceStatus` of `http://uri.etsi.org/19602/PidProvidersList/SvcStatus/notified` with a
 * `StatusStartingTime`.
 *
 * A valid Pub-EAA Providers List can list a service as
 * `http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn` (TS 119 602 H): don't trust it.
 * @param options.allowedTerritories - The accepted `SchemeTerritory` values, `['EU']` by default.
 * @returns Validation result with the issues of the document, and when valid the LoTEType of the
 * profile the document matches and the document typed as the `LoTEProfileDocument` of that profile
 *
 * @example
 * ```typescript
 * // The German PID Providers List declares DE as its territory and sets a service status
 * validateLoTEProfile(lote, LoTEProfile.EUPIDProvidersList, { mode: 'compat', allowedTerritories: ['DE'] })
 * ```
 */
export function validateLoTEProfile<P extends LoTEProfile, M extends LoTEValidationMode = 'strict'>(
  loteDocument: unknown,
  profile: P | P[],
  options: LoTEProfileValidationOptions<M> = {}
): LoTEProfileValidationResult<P, M> {
  const profiles = Array.isArray(profile) ? profile : [profile]
  const documentLoTEType = getDocumentLoTEType(loteDocument)

  // LoTEType is unique per profile, so at most one requested profile can match.
  const matchedProfile = profiles.find((p) => profileDefinitions[p].list.loTEType === documentLoTEType)

  if (matchedProfile) {
    const result = createProfileSchema(profileDefinitions[matchedProfile], options).safeParse(loteDocument)

    const issues = result.success
      ? []
      : result.error.issues.map((issue) => ({
          ...fromZodIssue(issue),
          message: `Profile ${matchedProfile}: ${issue.message}`,
        }))

    if (hasValidationErrors(issues)) {
      return { valid: false, issues }
    }

    // The type of the matched profile, which TypeScript can't relate to P
    return {
      valid: true,
      issues,
      loteType: profileDefinitions[matchedProfile].list.loTEType,
      lote: loteDocument,
    } as unknown as LoTEProfileValidationResult<P, M>
  }

  // No requested profile matches the document's LoTEType.
  return {
    valid: false,
    issues: profiles.map(
      (p): LoTEValidationIssue => ({
        severity: 'error',
        code: LOTE_VALIDATION_CODES.UNEXPECTED_LOTE_TYPE,
        path: ['LoTE', 'ListAndSchemeInformation', 'LoTEType'],
        message: `Profile ${p}: LoTEType must be ${profileDefinitions[p].list.loTEType}`,
      })
    ),
  }
}
