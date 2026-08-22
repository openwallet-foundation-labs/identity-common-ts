import type { z } from 'zod'
import { TrustedListParseException } from './trusted-list-exception'
import { type TrustedList, TrustedListSchema } from './types'

/** A single validation problem, mirroring `@owf/eudi-lote`'s ValidationError. */
export interface ValidationError {
  path: string
  message: string
}

/** Result of a validation, mirroring `@owf/eudi-lote`'s ValidationResult. */
export interface ValidationResult {
  valid: boolean
  errors: ValidationError[]
}

function fromZodError(error: z.ZodError): ValidationError[] {
  return error.issues.map((issue) => ({
    path: issue.path.map((p) => String(p)).join('.'),
    message: issue.message,
  }))
}

/**
 * Structurally validate an object against the ETSI TS 119 612 trusted-list
 * schema (the same zod-based approach `@owf/eudi-lote` uses for TS 119 602).
 * For XML input, parse it first with `parseTrustedList` (XML → object), then
 * validate the object here.
 */
export function validateTrustedList(value: unknown): ValidationResult {
  const result = TrustedListSchema.safeParse(value)
  return result.success ? { valid: true, errors: [] } : { valid: false, errors: fromZodError(result.error) }
}

/**
 * Structurally validate and return the typed trusted list, throwing
 * {@link TrustedListParseException} when it does not conform to the schema.
 */
export function assertValidTrustedList(value: unknown): TrustedList {
  const result = TrustedListSchema.safeParse(value)
  if (!result.success) {
    const details = fromZodError(result.error)
      .map((e) => `${e.path}: ${e.message}`)
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

function profileErrors(trustedList: TrustedList, rule: ProfileRule): ValidationError[] {
  const label = rule.name ?? 'profile'
  const errors: ValidationError[] = []

  if (stripScheme(trustedList.tslType) !== stripScheme(rule.tslType)) {
    errors.push({
      path: 'tslType',
      message: `[${label}] expected TSLType ${rule.tslType}, got ${trustedList.tslType ?? 'none'}`,
    })
  }

  const allowedTypes = new Set(rule.serviceTypes.map(stripScheme))
  const allowedStatuses = new Set(rule.serviceStatuses.map(stripScheme))
  trustedList.providers.forEach((provider, pi) => {
    provider.services.forEach((service, si) => {
      if (!allowedTypes.has(stripScheme(service.serviceTypeIdentifier))) {
        errors.push({
          path: `providers.${pi}.services.${si}.serviceTypeIdentifier`,
          message: `[${label}] unexpected service type ${service.serviceTypeIdentifier}`,
        })
      }
      if (!allowedStatuses.has(stripScheme(service.serviceStatus))) {
        errors.push({
          path: `providers.${pi}.services.${si}.serviceStatus`,
          message: `[${label}] unexpected service status ${service.serviceStatus}`,
        })
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
  if (perRule.some((errors) => errors.length === 0)) {
    return { valid: true, errors: [] }
  }
  return { valid: false, errors: perRule.flat() }
}
