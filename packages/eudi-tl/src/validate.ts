import { type Finding, hasErrorFindings, schemaIssueToFinding } from '@owf/identity-common'
import type { z } from 'zod'
import { TrustedListParseException } from './trusted-list-exception'
import { type TrustedList, TrustedListSchema } from './types'

/**
 * Codes for the profile checks, beyond schema parsing, whose issues carry the zod issue
 * code instead.
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

/** A finding of a trusted list validation, with a zod issue code for schema issues */
export type TrustedListFinding = Finding<TrustedListValidationCode | (string & {})>

/** A single validation problem, mirroring `@owf/eudi-lote`'s ValidationError. */
export interface ValidationError {
  path: string
  message: string
}

/** Result of a validation, mirroring `@owf/eudi-lote`'s ValidationResult. */
export interface ValidationResult {
  valid: boolean
  errors: ValidationError[]
  /** The errors as findings, with a code and with array indices as numbers in the path */
  findings: TrustedListFinding[]
}

function toResult(findings: TrustedListFinding[]): ValidationResult {
  return {
    valid: !hasErrorFindings(findings),
    errors: findings.map((finding) => ({ path: finding.path.join('.'), message: finding.message })),
    findings,
  }
}

function fromZodError(error: z.ZodError): TrustedListFinding[] {
  return error.issues.map((issue) => schemaIssueToFinding(issue))
}

/**
 * Structurally validate an object against the ETSI TS 119 612 trusted-list
 * schema (the same zod-based approach `@owf/eudi-lote` uses for TS 119 602).
 * For XML input, parse it first with `parseTrustedList` (XML → object), then
 * validate the object here.
 */
export function validateTrustedList(value: unknown): ValidationResult {
  const result = TrustedListSchema.safeParse(value)
  return toResult(result.success ? [] : fromZodError(result.error))
}

/**
 * Structurally validate and return the typed trusted list, throwing
 * {@link TrustedListParseException} when it does not conform to the schema.
 */
export function assertValidTrustedList(value: unknown): TrustedList {
  const result = TrustedListSchema.safeParse(value)
  if (!result.success) {
    const details = fromZodError(result.error)
      .map((e) => `${e.path.join('.')}: ${e.message}`)
      .join('; ')
    throw new TrustedListParseException(`Invalid trusted list: ${details}`)
  }
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

function profileErrors(trustedList: TrustedList, rule: ProfileRule): TrustedListFinding[] {
  const label = rule.name ?? 'profile'
  const errors: TrustedListFinding[] = []
  const add = (code: TrustedListValidationCode, path: (string | number)[], message: string) =>
    errors.push({ severity: 'error', code, path, message: `[${label}] ${message}` })

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

  return errors
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
  return toResult(perRule.some((errors) => errors.length === 0) ? [] : perRule.flat())
}
