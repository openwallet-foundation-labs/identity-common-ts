/**
 * LoTE Validator
 *
 * Runtime validation for ETSI TS 119 602 LoTE documents using Zod schemas.
 */

import {
  hasValidationErrors,
  parseWithSchema,
  type SchemaValidationCode,
  type ValidationIssueOf,
} from '@owf/identity-common'
import type z from 'zod'
import { LoteValidationError } from './lote-error'
import {
  createProfileSchema,
  type LoteProfileValidationOptions,
  type LoteValidationMode,
  profileDefinitions,
} from './profiles'
import { zCompatLoteDocument, zLoteDocument } from './schemas'
import type { CompatLoteDocument, LoteDocument } from './types'

/**
 * Codes for the profile checks of LoTE. The other checks have a code of
 * `SCHEMA_VALIDATION_CODES`.
 */
export const LOTE_VALIDATION_CODES = {
  /** `LoTEType` is not the one of any of the requested profiles */
  UNEXPECTED_LOTE_TYPE: 'unexpected_lote_type',
  /** `NextUpdate` is more than 6 months after `ListIssueDateTime` */
  NEXT_UPDATE_TOO_LATE: 'next_update_too_late',
} as const

/** A profile validation code emitted by this validator */
export type LoteValidationCode = (typeof LOTE_VALIDATION_CODES)[keyof typeof LOTE_VALIDATION_CODES]

/** An issue of a LoTE validation, with a code of `SCHEMA_VALIDATION_CODES` for schema issues */
export type LoteValidationIssue = ValidationIssueOf<LoteValidationCode | SchemaValidationCode>

/**
 * Validation result, with all issues of the document. When valid, `lote` is the validated
 * document, typed by what was validated.
 */
export type ValidationResult<T = LoteDocument> =
  | { valid: true; issues: LoteValidationIssue[]; lote: T }
  | { valid: false; issues: LoteValidationIssue[] }

/** The document `validateLote` accepts in a mode */
type ModeLoteDocument<M extends LoteValidationMode> = M extends 'compat' ? CompatLoteDocument : LoteDocument

/**
 * Validate a LoTE document against ETSI TS 119 602 schema
 *
 * @param loteDocument - The LoTE document to validate
 * @param options.mode - `compat` also accepts the `PolicyOrLegalNotice` of lists in use:
 * a `LoTELegalNotice` that is an array of localized URIs, and items with both keys. Defaults to `strict`.
 * @returns Validation result with the issues of the document, and when valid the document typed
 * as a `LoteDocument` (strict) or `CompatLoteDocument` (compat)
 *
 * @example
 * ```typescript
 * const result = validateLote(myLote);
 * if (!result.valid) {
 *   console.error('Validation issues:', result.issues);
 * }
 * ```
 */
export function validateLote<M extends LoteValidationMode = 'strict'>(
  loteDocument: unknown,
  { mode }: { mode?: M } = {}
): ValidationResult<ModeLoteDocument<M>> {
  const result = parseWithSchema(mode === 'compat' ? zCompatLoteDocument : zLoteDocument, loteDocument, {
    codes: LOTE_VALIDATION_CODES,
  })
  const issues = result.success ? [] : result.issues

  if (hasValidationErrors(issues)) {
    return { valid: false, issues }
  }

  // The input, not the parsed copy: that drops the keys the schema doesn't know
  return { valid: true, issues, lote: loteDocument as ModeLoteDocument<M> }
}

/**
 * Assert that a LoTE document is valid, throwing if not
 *
 * @param loteDocument - The LoTE document to validate
 * @param options.mode - As in `validateLote`. Defaults to `strict`.
 * @throws LoteValidationError with the issues of the validation if it fails
 */
export function assertValidLote<M extends LoteValidationMode = 'strict'>(
  loteDocument: unknown,
  options: { mode?: M } = {}
): asserts loteDocument is ModeLoteDocument<M> {
  const result = validateLote(loteDocument, options)
  if (!result.valid) throw new LoteValidationError('Invalid LoTE document', result.issues)
}

/**
 * Supported LoTE profiles for validation
 */
export enum LoteProfile {
  EuPidProvidersList = 'EuPidProvidersList',
  EuWalletProvidersList = 'EuWalletProvidersList',
  EuWrpacProvidersList = 'EuWrpacProvidersList',
  EuWrprcProvidersList = 'EuWrprcProvidersList',
  EuEaaProvidersList = 'EuEaaProvidersList',
  EuPubEaaProvidersList = 'EuPubEaaProvidersList',
  MdlProvidersList = 'MdlProvidersList',
}

/**
 * The document a profile accepts in a mode, with the profile's LoTEType, ServiceTypeIdentifier
 * and ServiceStatus values as literal types
 */
export type LoteProfileDocument<P extends LoteProfile, M extends LoteValidationMode = 'strict'> = P extends LoteProfile
  ? z.output<ReturnType<typeof createProfileSchema<(typeof profileDefinitions)[P], M>>>
  : never

/**
 * Validation result of `validateLoteProfile`. When valid, `loteType` is the LoTEType of the
 * profile the document matches, and narrows `lote` to the `LoteProfileDocument` of that profile.
 * A Pub-EAA Providers List also has `notifiedTrustedEntities` (see `getNotifiedTrustedEntities`).
 */
export type LoteProfileValidationResult<P extends LoteProfile, M extends LoteValidationMode = 'strict'> =
  | (P extends LoteProfile
      ? {
          valid: true
          issues: LoteValidationIssue[]
          loteType: (typeof profileDefinitions)[P]['list']['loteType']
          lote: LoteProfileDocument<P, M>
        } & (P extends LoteProfile.EuPubEaaProvidersList
          ? { notifiedTrustedEntities: NonNullable<LoteProfileDocument<P, M>['LoTE']['TrustedEntitiesList']> }
          : unknown)
      : never)
  | { valid: false; issues: LoteValidationIssue[] }

function getDocumentLoteType(loteDocument: unknown): string | undefined {
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
 * `PolicyOrLegalNotice` that `validateLote` accepts in compat mode, on a PID Providers List a
 * `ServiceStatus` of `http://uri.etsi.org/19602/PidProvidersList/SvcStatus/notified` with a
 * `StatusStartingTime`, and on a Pub-EAA Providers List no `HistoricalInformationPeriod` and the
 * `http://uri.etsi.org/19602/ListOfTrustedEntities/PubEAAProvider/CC` URI in `TEInformationURI` instead
 * of `TEAddress.TEElectronicAddress` (TS 119 602 H.2).
 *
 * A valid Pub-EAA Providers List can list a service as
 * `http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn` (TS 119 602 H): don't trust it.
 * The valid result has them left out in `notifiedTrustedEntities`.
 * @param options.allowedTerritories - Compat mode only. The accepted `SchemeTerritory` values,
 * `['EU']` by default.
 * @throws LoteError if `allowedTerritories` is passed in strict mode
 * @returns Validation result with the issues of the document, and when valid the LoTEType of the
 * profile the document matches and the document typed as the `LoteProfileDocument` of that profile
 *
 * @example
 * ```typescript
 * // The German PID Providers List declares DE as its territory and sets a service status
 * validateLoteProfile(lote, LoteProfile.EuPidProvidersList, { mode: 'compat', allowedTerritories: ['DE'] })
 * ```
 */
export function validateLoteProfile<P extends LoteProfile, M extends LoteValidationMode = 'strict'>(
  loteDocument: unknown,
  profile: P | P[],
  options: LoteProfileValidationOptions<M> = {}
): LoteProfileValidationResult<P, M> {
  const profiles = Array.isArray(profile) ? profile : [profile]
  const documentLoteType = getDocumentLoteType(loteDocument)

  // LoTEType is unique per profile, so at most one requested profile can match.
  const matchedProfile = profiles.find((p) => profileDefinitions[p].list.loteType === documentLoteType)

  if (matchedProfile) {
    const result = parseWithSchema(createProfileSchema(profileDefinitions[matchedProfile], options), loteDocument, {
      codes: LOTE_VALIDATION_CODES,
    })

    const issues = result.success
      ? []
      : result.issues.map((issue) => ({ ...issue, message: `Profile ${matchedProfile}: ${issue.message}` }))

    if (hasValidationErrors(issues)) {
      return { valid: false, issues }
    }

    // The type of the matched profile, which TypeScript can't relate to P
    return {
      valid: true,
      issues,
      loteType: profileDefinitions[matchedProfile].list.loteType,
      lote: loteDocument,
      // Only a Pub-EAA Providers List can list withdrawn services (TS 119 602 H)
      ...(matchedProfile === LoteProfile.EuPubEaaProvidersList && {
        notifiedTrustedEntities: getNotifiedTrustedEntities(
          loteDocument as LoteProfileDocument<LoteProfile.EuPubEaaProvidersList>
        ),
      }),
    } as unknown as LoteProfileValidationResult<P, M>
  }

  // No requested profile matches the document's LoTEType.
  return {
    valid: false,
    issues: profiles.map(
      (p): LoteValidationIssue => ({
        severity: 'error',
        code: LOTE_VALIDATION_CODES.UNEXPECTED_LOTE_TYPE,
        path: ['LoTE', 'ListAndSchemeInformation', 'LoTEType'],
        message: `Profile ${p}: LoTEType must be ${profileDefinitions[p].list.loteType}`,
      })
    ),
  }
}

// A service without ServiceStatus is notified: only the PID compat and Pub-EAA profiles define one
const NOTIFIED_SERVICE_STATUSES: readonly (string | undefined)[] = [
  undefined,
  'http://uri.etsi.org/19602/PidProvidersList/SvcStatus/notified',
  'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified',
]

/**
 * The trusted entities of a list validated with `validateLoteProfile`, with only their notified
 * services. This leaves out the withdrawn services a valid Pub-EAA Providers List can list
 * (TS 119 602 H), and the entities that have no notified service left.
 *
 * @example
 * ```typescript
 * const result = validateLoteProfile(lote, LoteProfile.EuPubEaaProvidersList);
 * if (result.valid) {
 *   const trustedEntities = getNotifiedTrustedEntities(result.lote);
 * }
 * ```
 */
export function getNotifiedTrustedEntities<D extends LoteProfileDocument<LoteProfile, LoteValidationMode>>(
  lote: D
): NonNullable<D['LoTE']['TrustedEntitiesList']> {
  return (lote.LoTE.TrustedEntitiesList ?? []).flatMap((entity) => {
    const services = entity.TrustedEntityServices.filter((service) =>
      NOTIFIED_SERVICE_STATUSES.includes(service.ServiceInformation.ServiceStatus)
    )
    return services.length ? [{ ...entity, TrustedEntityServices: services }] : []
  }) as NonNullable<D['LoTE']['TrustedEntitiesList']>
}
