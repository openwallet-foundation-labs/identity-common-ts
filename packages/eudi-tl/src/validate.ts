import {
  type ValidationResult as CommonValidationResult,
  parseWithSchema,
  type SchemaValidationCode,
  toValidationResult,
  type ValidationIssueOf,
  ValidationIssues,
} from '@owf/identity-common'
import { TrustedListValidationError } from './trusted-list-error'
import { type TrustedList, zTrustedList } from './types'

/**
 * Codes for the profile checks, beyond schema parsing, whose issues have a code of
 * `SCHEMA_VALIDATION_CODES` instead.
 */
export const TRUSTED_LIST_VALIDATION_CODES = {
  /** `TSLType` differs from the one of the profile */
  UNEXPECTED_TSL_TYPE: 'unexpected_tsl_type',
  /** A service type identifier the profile does not permit */
  UNEXPECTED_SERVICE_TYPE: 'unexpected_service_type',
  /** A service status the profile does not permit */
  UNEXPECTED_SERVICE_STATUS: 'unexpected_service_status',
} as const

/** A profile validation code emitted by this validator */
export type TrustedListValidationCode =
  (typeof TRUSTED_LIST_VALIDATION_CODES)[keyof typeof TRUSTED_LIST_VALIDATION_CODES]

/** An issue of a trusted list validation, with a code of `SCHEMA_VALIDATION_CODES` for schema issues */
export type TrustedListValidationIssue = ValidationIssueOf<TrustedListValidationCode | SchemaValidationCode>

/** Result of a validation, the same as `@owf/eudi-lote`'s ValidationResult */
export type ValidationResult = CommonValidationResult<TrustedListValidationIssue>

const parseTrustedListSchema = (value: unknown) =>
  parseWithSchema(zTrustedList, value, { codes: TRUSTED_LIST_VALIDATION_CODES })

/**
 * Structurally validate an object against the ETSI TS 119 612 trusted-list
 * schema (the same zod-based approach `@owf/eudi-lote` uses for TS 119 602).
 * For XML input, parse it first with `parseTrustedList` (XML → object), then
 * validate the object here.
 */
export function validateTrustedList(value: unknown): ValidationResult {
  const result = parseTrustedListSchema(value)
  return toValidationResult(result.success ? [] : result.issues)
}

/**
 * Structurally validate and return the typed trusted list, throwing
 * {@link TrustedListValidationError} when it does not conform to the schema.
 */
export function assertValidTrustedList(value: unknown): TrustedList {
  const result = parseTrustedListSchema(value)
  if (!result.success) throw new TrustedListValidationError('Invalid trusted list', result.issues)
  return result.data
}

/**
 * A profile constraint set for a trusted list: the expected `TSLType` and the
 * service type / status URIs the profile permits. The zod-based structural
 * schema ({@link validateTrustedList}) is checked first; a profile then narrows
 * a conforming list to a specific ecosystem. Rules are supplied by the caller,
 * so the library stays profile-agnostic (mirrors `@owf/eudi-lote`'s approach).
 */
export interface ProfileRule {
  /** Optional label used in error messages. */
  name?: string
  /** Expected `TSLType` (compared scheme-insensitively). */
  tslType: string
  /** Service type URIs the profile permits (scheme-insensitive). */
  serviceTypes: string[]
  /** Service status URIs the profile permits (scheme-insensitive). */
  serviceStatuses: string[]
}

/**
 * Compare ETSI URIs scheme-insensitively: deployed lists have published the
 * same URI over both `http` and `https`. Internal helper, not part of the
 * package's public API.
 */
export const stripScheme = (uri: string | undefined): string => (uri ?? '').replace(/^https?:\/\//, '')

function profileErrors(trustedList: TrustedList, rule: ProfileRule): TrustedListValidationIssue[] {
  const label = rule.name ?? 'profile'
  const issues = new ValidationIssues<TrustedListValidationCode>()
  const add = (code: TrustedListValidationCode, path: (string | number)[], message: string) =>
    issues.add({ code, path, message: `[${label}] ${message}` })

  if (stripScheme(trustedList.tslType) !== stripScheme(rule.tslType)) {
    add(
      TRUSTED_LIST_VALIDATION_CODES.UNEXPECTED_TSL_TYPE,
      ['tslType'],
      `expected TSLType ${rule.tslType}, got ${trustedList.tslType ?? 'none'}`
    )
  }

  const allowedTypes = new Set(rule.serviceTypes.map(stripScheme))
  const allowedStatuses = new Set(rule.serviceStatuses.map(stripScheme))
  trustedList.providers.forEach((provider, pi) => {
    provider.services.forEach((service, si) => {
      const servicePath = ['providers', pi, 'services', si]
      if (!allowedTypes.has(stripScheme(service.serviceTypeIdentifier))) {
        add(
          TRUSTED_LIST_VALIDATION_CODES.UNEXPECTED_SERVICE_TYPE,
          [...servicePath, 'serviceTypeIdentifier'],
          `unexpected service type ${service.serviceTypeIdentifier}`
        )
      }
      if (!allowedStatuses.has(stripScheme(service.serviceStatus))) {
        add(
          TRUSTED_LIST_VALIDATION_CODES.UNEXPECTED_SERVICE_STATUS,
          [...servicePath, 'serviceStatus'],
          `unexpected service status ${service.serviceStatus}`
        )
      }
    })
  })

  return issues.issues
}

/**
 * Validate that a trusted list conforms to one (or any, given several) of the
 * supplied profile rules — structural schema first, then profile-specific
 * constraints. Mirrors `@owf/eudi-lote`'s profile validation.
 */
export function validateTrustedListProfile(value: unknown, rule: ProfileRule | ProfileRule[]): ValidationResult {
  const structural = validateTrustedList(value)
  if (!structural.valid) return structural

  const trustedList = value as TrustedList
  const rules = Array.isArray(rule) ? rule : [rule]
  const perRule = rules.map((r) => profileErrors(trustedList, r))
  return toValidationResult(perRule.some((errors) => errors.length === 0) ? [] : perRule.flat())
}
