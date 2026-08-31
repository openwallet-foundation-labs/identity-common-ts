/**
 * WRPRC Validator
 *
 * Validation functions for ETSI TS 119 475 Wallet-Relying Party Registration Certificates.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import { secondsToDate } from '@owf/identity-common'
import { normalizeWRPRCPayload } from './dialect'
import { ALL_ENTITLEMENTS, ALL_PSP_SUB_ENTITLEMENTS, ATTESTATION_PROVIDER_ENTITLEMENTS } from './entitlements'
import {
  LegalPersonSubjectSchema,
  NaturalPersonSubjectSchema,
  WRPRCJWTHeaderSchema,
  WRPRCPayloadSchema,
} from './schemas'
import type { WRPRCPayload } from './types'
import { WRPRCException } from './wrprc-exception'

// ============================================================================
// Validation Result Types
// ============================================================================

/**
 * Codes for the semantic checks this validator performs, beyond schema parsing.
 *
 * Exposed so a calling application can branch on a specific failure rather than
 * matching on message text. Requirement identifiers from ETSI TS 119 475 v1.2.1
 * are given where a code maps to one.
 */
export const WRPRC_VALIDATION_CODES = {
  /** No entitlement present (GEN-5.2.4-03) */
  MISSING_ENTITLEMENT: 'missing_entitlement',
  /** Sub-entitlement present without its base entitlement (GEN-5.2.4-04) */
  MISSING_BASE_ENTITLEMENT: 'missing_base_entitlement',
  /** Entitlement outside Annex A, which may be a national or EU extension */
  UNKNOWN_ENTITLEMENT: 'unknown_entitlement',
  /** Attestation provider without provides_attestations (GEN-5.2.4-05) */
  MISSING_PROVIDES_ATTESTATIONS: 'missing_provides_attestations',
  /** Service provider without credentials (GEN-5.2.4-06, Table 9) */
  MISSING_CREDENTIALS: 'missing_credentials',
  /** Service provider without purpose (GEN-5.2.4-06, Table 9) */
  MISSING_PURPOSE: 'missing_purpose',
  /** sub does not follow the semantic identifier format of clause 5.1 */
  INVALID_SEMANTIC_IDENTIFIER: 'invalid_semantic_identifier',
  /** sub uses initial characters outside Tables 2 and 4, which may be a national scheme */
  UNKNOWN_IDENTIFIER_PREFIX: 'unknown_identifier_prefix',
  /** sub parses but deviates from the expected identifier shape */
  IDENTIFIER_FORMAT_WARNING: 'identifier_format_warning',
  /** exp more than 12 months after iat (GEN-5.2.4-08) */
  EXP_TOO_LATE: 'exp_too_late',
  /** exp at or before iat */
  EXP_BEFORE_IAT: 'exp_before_iat',
  /** intermediary present without act (GEN-5.2.4-09) */
  MISSING_ACT: 'missing_act',
  /** act.sub does not match intermediary.sub (GEN-5.2.4-09) */
  ACT_INTERMEDIARY_MISMATCH: 'act_intermediary_mismatch',
} as const

/** A semantic validation code emitted by this validator */
export type WRPRCValidationCode = (typeof WRPRC_VALIDATION_CODES)[keyof typeof WRPRC_VALIDATION_CODES]

/**
 * A single validation error
 */
export interface ValidationError {
  /** Path to the invalid field */
  path: string[]
  /** Error message */
  message: string
  /**
   * Error code. Either a `WRPRCValidationCode` from the semantic checks, or a zod issue
   * code forwarded from schema parsing, so the string stays open for the latter.
   */
  code: WRPRCValidationCode | (string & {})
}

/**
 * Result of WRPRC validation
 */
export interface ValidationResult {
  /** Whether the WRPRC is valid */
  valid: boolean
  /** List of validation errors (empty if valid) */
  errors: ValidationError[]
  /** Warnings that don't invalidate the certificate but should be noted */
  warnings: ValidationError[]
}

// ============================================================================
// Core Validation Functions
// ============================================================================

/**
 * Entitlement-driven checks: GEN-5.2.4-03 to GEN-5.2.4-06.
 */
function validateEntitlementRequirements(
  payload: WRPRCPayload,
  errors: ValidationError[],
  warnings: ValidationError[]
): void {
  for (const entitlement of payload.entitlements) {
    const known =
      ALL_ENTITLEMENTS.includes(entitlement as (typeof ALL_ENTITLEMENTS)[number]) ||
      ALL_PSP_SUB_ENTITLEMENTS.includes(entitlement as (typeof ALL_PSP_SUB_ENTITLEMENTS)[number])
    if (!known) {
      warnings.push({
        path: ['entitlements'],
        message: `Unknown entitlement URI: ${entitlement}. This may be a national or EU-defined extension.`,
        code: WRPRC_VALIDATION_CODES.UNKNOWN_ENTITLEMENT,
      })
    }
  }

  // GEN-5.2.4-03: At least one entitlement must be specified
  if (payload.entitlements.length === 0) {
    errors.push({
      path: ['entitlements'],
      message: 'At least one entitlement must be specified (GEN-5.2.4-03)',
      code: WRPRC_VALIDATION_CODES.MISSING_ENTITLEMENT,
    })
  }

  const hasSubEntitlement = payload.entitlements.some((e) =>
    ALL_PSP_SUB_ENTITLEMENTS.includes(e as (typeof ALL_PSP_SUB_ENTITLEMENTS)[number])
  )
  const hasServiceProvider = payload.entitlements.includes('https://uri.etsi.org/19475/Entitlement/Service_Provider')

  // GEN-5.2.4-04: If sub-entitlements are present, a base entitlement must also be present
  if (hasSubEntitlement && !hasServiceProvider) {
    errors.push({
      path: ['entitlements'],
      message: 'Service provider sub-entitlements require Service_Provider entitlement (GEN-5.2.4-04)',
      code: WRPRC_VALIDATION_CODES.MISSING_BASE_ENTITLEMENT,
    })
  }

  // GEN-5.2.4-05: Attestation providers should have provides_attestations
  const hasAttestationProviderRole = payload.entitlements.some((e) =>
    ATTESTATION_PROVIDER_ENTITLEMENTS.includes(e as (typeof ATTESTATION_PROVIDER_ENTITLEMENTS)[number])
  )
  if (hasAttestationProviderRole && !payload.provides_attestations) {
    warnings.push({
      path: ['provides_attestations'],
      message:
        'Attestation providers should include provides_attestations field (GEN-5.2.4-05). This is recommended but not required.',
      code: WRPRC_VALIDATION_CODES.MISSING_PROVIDES_ATTESTATIONS,
    })
  }

  // GEN-5.2.4-06: service providers carry the intended use fields of Table 9. The registry
  // may not have provided them, so these are warnings rather than errors.
  if (hasServiceProvider && !payload.credentials) {
    warnings.push({
      path: ['credentials'],
      message: 'Service provider WRPRCs should include the credentials field (GEN-5.2.4-06)',
      code: WRPRC_VALIDATION_CODES.MISSING_CREDENTIALS,
    })
  }
  if (hasServiceProvider && !payload.purpose) {
    warnings.push({
      path: ['purpose'],
      message: 'Service provider WRPRCs should include the purpose field (GEN-5.2.4-06)',
      code: WRPRC_VALIDATION_CODES.MISSING_PURPOSE,
    })
  }
}

/**
 * Validate a WRPRC payload against the schema
 */
export function validateWRPRCPayload(payload: unknown): ValidationResult {
  const result = WRPRCPayloadSchema.safeParse(normalizeWRPRCPayload(payload))
  const errors: ValidationError[] = []
  const warnings: ValidationError[] = []

  if (!result.success) {
    for (const issue of result.error.issues) {
      errors.push({
        path: issue.path.map(String),
        message: issue.message,
        code: issue.code,
      })
    }
    return { valid: false, errors, warnings }
  }

  // Additional semantic validations
  const validPayload: WRPRCPayload = result.data

  validateEntitlementRequirements(validPayload, errors, warnings)

  // Validate subject identifier format (semantic identifier)
  const subResult = validateSemanticIdentifier(validPayload.sub)
  if (!subResult.valid) {
    errors.push({
      path: ['sub'],
      message: subResult.message,
      code: WRPRC_VALIDATION_CODES.INVALID_SEMANTIC_IDENTIFIER,
    })
  } else if (subResult.unknownPrefix) {
    warnings.push({
      path: ['sub'],
      message: `Unknown semantic identifier initial characters: ${subResult.unknownPrefix}. This may be a national scheme (ETSI EN 319 412-1).`,
      code: WRPRC_VALIDATION_CODES.UNKNOWN_IDENTIFIER_PREFIX,
    })
  }

  // GEN-5.2.4-08: exp must be at most 12 months after iat
  if (typeof validPayload.exp === 'number') {
    const maxExp = secondsToDate(validPayload.iat)
    maxExp.setUTCFullYear(maxExp.getUTCFullYear() + 1)
    if (secondsToDate(validPayload.exp) > maxExp) {
      errors.push({
        path: ['exp'],
        message: 'exp must be at most 12 months after iat (GEN-5.2.4-08)',
        code: WRPRC_VALIDATION_CODES.EXP_TOO_LATE,
      })
    }
    if (validPayload.exp <= validPayload.iat) {
      errors.push({
        path: ['exp'],
        message: 'exp must be after iat',
        code: WRPRC_VALIDATION_CODES.EXP_BEFORE_IAT,
      })
    }
  }

  // GEN-5.2.4-09: under intermediation, act.sub must match intermediary.sub
  if (validPayload.intermediary) {
    if (!validPayload.act) {
      errors.push({
        path: ['act'],
        message: 'act claim is required when an intermediary is present (GEN-5.2.4-09)',
        code: WRPRC_VALIDATION_CODES.MISSING_ACT,
      })
    } else if (validPayload.act.sub !== validPayload.intermediary.sub) {
      errors.push({
        path: ['act', 'sub'],
        message: 'act.sub must match intermediary.sub (GEN-5.2.4-09)',
        code: WRPRC_VALIDATION_CODES.ACT_INTERMEDIARY_MISMATCH,
      })
    }
  }

  return { valid: errors.length === 0, errors, warnings }
}

/**
 * Validate a JWT header for WRPRC
 */
export function validateWRPRCJWTHeader(header: unknown): ValidationResult {
  const result = WRPRCJWTHeaderSchema.safeParse(header)
  const errors: ValidationError[] = []
  const warnings: ValidationError[] = []

  if (!result.success) {
    for (const issue of result.error.issues) {
      errors.push({
        path: issue.path.map(String),
        message: issue.message,
        code: issue.code,
      })
    }
  }

  return { valid: errors.length === 0, errors, warnings }
}

/**
 * Validate a complete WRPRC (header + payload)
 */
export function validateWRPRC(header: unknown, payload: unknown): ValidationResult {
  const headerResult = validateWRPRCJWTHeader(header)
  const payloadResult = validateWRPRCPayload(payload)

  const errors = [
    ...headerResult.errors.map((e) => ({ ...e, path: ['header', ...e.path] })),
    ...payloadResult.errors.map((e) => ({ ...e, path: ['payload', ...e.path] })),
  ]

  const warnings = [
    ...headerResult.warnings.map((w) => ({ ...w, path: ['header', ...w.path] })),
    ...payloadResult.warnings.map((w) => ({ ...w, path: ['payload', ...w.path] })),
  ]

  return { valid: errors.length === 0, errors, warnings }
}

// ============================================================================
// Subject Type Validation
// ============================================================================

/**
 * Check if payload represents a legal person
 */
export function isLegalPersonWRPRC(payload: WRPRCPayload): boolean {
  return typeof payload.sub_ln === 'string' && payload.sub_ln.length > 0
}

/**
 * Check if payload represents a natural person
 */
export function isNaturalPersonWRPRC(payload: WRPRCPayload): boolean {
  return (
    typeof payload.sub_gn === 'string' &&
    payload.sub_gn.length > 0 &&
    typeof payload.sub_fn === 'string' &&
    payload.sub_fn.length > 0
  )
}

/**
 * Validate as legal person WRPRC
 */
export function validateLegalPersonWRPRC(payload: unknown): ValidationResult {
  const result = LegalPersonSubjectSchema.safeParse(normalizeWRPRCPayload(payload))
  const errors: ValidationError[] = []
  const warnings: ValidationError[] = []

  if (!result.success) {
    for (const issue of result.error.issues) {
      errors.push({
        path: issue.path.map(String),
        message: issue.message,
        code: issue.code,
      })
    }
  }

  // Additional validation for legal person identifier format
  if (result.success) {
    const sub: string = result.data.sub
    // Legal person identifiers should follow ETSI EN 319 412-1 clause 5.1.4
    // Format: 3-letter prefix + 2-letter country code + hyphen + identifier
    if (!/^[A-Z]{3}[A-Z]{2}-.+$/.test(sub)) {
      warnings.push({
        path: ['sub'],
        message:
          'Legal person identifier should follow format: PREFIX + COUNTRY + "-" + ID (e.g., "LEIXG-529900T8BM49AURSDO55")',
        code: WRPRC_VALIDATION_CODES.IDENTIFIER_FORMAT_WARNING,
      })
    }
  }

  return { valid: errors.length === 0, errors, warnings }
}

/**
 * Validate as natural person WRPRC
 */
export function validateNaturalPersonWRPRC(payload: unknown): ValidationResult {
  const result = NaturalPersonSubjectSchema.safeParse(normalizeWRPRCPayload(payload))
  const errors: ValidationError[] = []
  const warnings: ValidationError[] = []

  if (!result.success) {
    for (const issue of result.error.issues) {
      errors.push({
        path: issue.path.map(String),
        message: issue.message,
        code: issue.code,
      })
    }
  }

  // Additional validation for natural person identifier format
  if (result.success) {
    const sub: string = result.data.sub
    // Natural person identifiers should follow ETSI EN 319 412-1 clause 5.1.3
    // Format: 3-letter prefix + 2-letter country code + hyphen + identifier
    if (!/^[A-Z]{3}[A-Z]{2}-.+$/.test(sub)) {
      warnings.push({
        path: ['sub'],
        message:
          'Natural person identifier should follow format: PREFIX + COUNTRY + "-" + ID (e.g., "TINIT-RSSMRA85T10A562S")',
        code: WRPRC_VALIDATION_CODES.IDENTIFIER_FORMAT_WARNING,
      })
    }
  }

  return { valid: errors.length === 0, errors, warnings }
}

// ============================================================================
// Semantic Identifier Validation
// ============================================================================

/**
 * Valid semantic identifier initial characters for legal persons
 * (Table 2, ETSI EN 319 412-1 clause 5.1.4)
 */
const LEGAL_PERSON_PREFIXES = ['EOR', 'LEI', 'NTR', 'VAT', 'EXC']

/**
 * Valid semantic identifier initial characters for natural persons
 * (Table 4, ETSI EN 319 412-1 clause 5.1.3)
 */
const NATURAL_PERSON_PREFIXES = ['TIN', 'PAS', 'IDC', 'PNO']

/**
 * Validate a semantic identifier format
 */
function validateSemanticIdentifier(identifier: string): {
  valid: boolean
  message: string
  unknownPrefix?: string
} {
  // Format: PREFIX (3 chars) + COUNTRY (2 chars) + "-" + ID
  const match = identifier.match(/^([A-Z]{3})([A-Z]{2})-(.+)$/)

  if (!match) {
    return {
      valid: false,
      message: 'Semantic identifier must follow format: PREFIX (3 chars) + COUNTRY (2 chars) + "-" + ID',
    }
  }

  const [, prefix] = match
  const known = LEGAL_PERSON_PREFIXES.includes(prefix) || NATURAL_PERSON_PREFIXES.includes(prefix)

  // National schemes may define further initial characters, so an unknown one is not an error
  return { valid: true, message: '', ...(known ? {} : { unknownPrefix: prefix }) }
}

// ============================================================================
// Assertion Functions
// ============================================================================

/**
 * Assert that a WRPRC payload is valid, throws WRPRCException if not
 */
export function assertValidWRPRCPayload(payload: unknown): asserts payload is WRPRCPayload {
  const result = validateWRPRCPayload(payload)
  if (!result.valid) {
    const messages = result.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('\n')
    throw new WRPRCException(`Invalid WRPRC payload:\n${messages}`, result.errors)
  }
}

/**
 * Parse a WRPRC payload into its canonical form, accepting either dialect spelling.
 *
 * @throws WRPRCException if the payload is invalid
 */
export function parseWRPRCPayload(payload: unknown): WRPRCPayload {
  assertValidWRPRCPayload(payload)
  return WRPRCPayloadSchema.parse(normalizeWRPRCPayload(payload))
}

/**
 * Assert that a WRPRC is valid (header + payload), throws WRPRCException if not
 */
export function assertValidWRPRC(header: unknown, payload: unknown): void {
  const result = validateWRPRC(header, payload)
  if (!result.valid) {
    const messages = result.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('\n')
    throw new WRPRCException(`Invalid WRPRC:\n${messages}`, result.errors)
  }
}
