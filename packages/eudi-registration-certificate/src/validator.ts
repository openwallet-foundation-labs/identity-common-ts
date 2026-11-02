/**
 * Registration Certificate Validator
 *
 * Validation functions for ETSI TS 119 475 Wallet-Relying Party Registration Certificates.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import {
  type ValidationResult as CommonValidationResult,
  parseWithSchema,
  prefixIssuePaths,
  type SchemaValidationCode,
  secondsToDate,
  toValidationResult,
  VALIDATION_CODES,
  type ValidationIssueOf,
  ValidationIssues,
} from '@owf/identity-common'
import type { z } from 'zod'
import { normalizeRegistrationCertificatePayload } from './dialect'
import { ALL_ENTITLEMENTS, ALL_PSP_SUB_ENTITLEMENTS, ATTESTATION_PROVIDER_ENTITLEMENTS } from './entitlements'
import { RegistrationCertificateValidationError } from './registration-certificate-error'
import {
  zLegalPersonSubject,
  zNaturalPersonSubject,
  zRegistrationCertificateJWTHeader,
  zRegistrationCertificatePayload,
} from './schemas'
import type { RegistrationCertificatePayload } from './types'

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
export const REGISTRATION_CERTIFICATE_VALIDATION_CODES = {
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
  /** exp at or before iat, with `issuedAt` and `expiresAt` as context */
  EXPIRES_BEFORE_ISSUED: VALIDATION_CODES.EXPIRES_BEFORE_ISSUED,
  /** typ of the JWT header is not rc-wrp+jwt, with `expected` and `actual` as context */
  INVALID_TYP: VALIDATION_CODES.INVALID_TYP,
  /** Selected registration certificate identity does not match the access certificate subject */
  ACCESS_CERTIFICATE_IDENTITY_MISMATCH: 'access_certificate_identity_mismatch',
} as const

/** A semantic validation code emitted by this validator */
export type RegistrationCertificateValidationCode =
  (typeof REGISTRATION_CERTIFICATE_VALIDATION_CODES)[keyof typeof REGISTRATION_CERTIFICATE_VALIDATION_CODES]

/**
 * An issue of a registration certificate validation, with a `RegistrationCertificateValidationCode` from the semantic checks or
 * a code of `SCHEMA_VALIDATION_CODES` from schema parsing. `requirement` is the ETSI TS 119 475 requirement.
 */
export type RegistrationCertificateValidationIssue = ValidationIssueOf<
  RegistrationCertificateValidationCode | SchemaValidationCode
>

/**
 * Result of registration certificate validation: errors make the registration certificate invalid, warnings don't but should be
 * noted
 */
export type ValidationResult = CommonValidationResult<RegistrationCertificateValidationIssue>

/** Parse with a schema of this package, with its schema issues as a result when it fails */
const parseRegistrationCertificateSchema = <Schema extends z.ZodType>(schema: Schema, value: unknown) =>
  parseWithSchema(schema, value, { codes: REGISTRATION_CERTIFICATE_VALIDATION_CODES })

// ============================================================================
// Core Validation Functions
// ============================================================================

/**
 * Entitlement-driven checks: GEN-5.2.4-03 to GEN-5.2.4-06.
 */
function validateEntitlementRequirements(
  payload: RegistrationCertificatePayload,
  issues: ValidationIssues<RegistrationCertificateValidationCode>
): void {
  for (const entitlement of payload.entitlements) {
    const known =
      ALL_ENTITLEMENTS.includes(entitlement as (typeof ALL_ENTITLEMENTS)[number]) ||
      ALL_PSP_SUB_ENTITLEMENTS.includes(entitlement as (typeof ALL_PSP_SUB_ENTITLEMENTS)[number])
    if (!known) {
      issues.add({
        severity: 'warning',
        path: ['entitlements'],
        message: `Unknown entitlement URI: ${entitlement}. This may be a national or EU-defined extension.`,
        code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.UNKNOWN_ENTITLEMENT,
      })
    }
  }

  // GEN-5.2.4-03: At least one entitlement must be specified
  if (payload.entitlements.length === 0) {
    issues.add({
      path: ['entitlements'],
      message: 'At least one entitlement must be specified (GEN-5.2.4-03)',
      code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.MISSING_ENTITLEMENT,
      requirement: 'GEN-5.2.4-03',
    })
  }

  const hasSubEntitlement = payload.entitlements.some((e) =>
    ALL_PSP_SUB_ENTITLEMENTS.includes(e as (typeof ALL_PSP_SUB_ENTITLEMENTS)[number])
  )
  const hasServiceProvider = payload.entitlements.includes('https://uri.etsi.org/19475/Entitlement/Service_Provider')

  // GEN-5.2.4-04: If sub-entitlements are present, a base entitlement must also be present
  if (hasSubEntitlement && !hasServiceProvider) {
    issues.add({
      path: ['entitlements'],
      message: 'Service provider sub-entitlements require Service_Provider entitlement (GEN-5.2.4-04)',
      code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.MISSING_BASE_ENTITLEMENT,
      requirement: 'GEN-5.2.4-04',
    })
  }

  // GEN-5.2.4-05: Attestation providers should have provides_attestations
  const hasAttestationProviderRole = payload.entitlements.some((e) =>
    ATTESTATION_PROVIDER_ENTITLEMENTS.includes(e as (typeof ATTESTATION_PROVIDER_ENTITLEMENTS)[number])
  )
  if (hasAttestationProviderRole && !payload.provides_attestations) {
    issues.add({
      severity: 'warning',
      path: ['provides_attestations'],
      message:
        'Attestation providers should include provides_attestations field (GEN-5.2.4-05). This is recommended but not required.',
      code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.MISSING_PROVIDES_ATTESTATIONS,
      requirement: 'GEN-5.2.4-05',
    })
  }

  // GEN-5.2.4-06: service providers carry the intended use fields of Table 9. The registry
  // may not have provided them, so these are warnings rather than errors.
  if (hasServiceProvider && !payload.credentials) {
    issues.add({
      severity: 'warning',
      path: ['credentials'],
      message: 'Service provider registration certificates should include the credentials field (GEN-5.2.4-06)',
      code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.MISSING_CREDENTIALS,
      requirement: 'GEN-5.2.4-06',
    })
  }
  if (hasServiceProvider && !payload.purpose) {
    issues.add({
      severity: 'warning',
      path: ['purpose'],
      message: 'Service provider registration certificates should include the purpose field (GEN-5.2.4-06)',
      code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.MISSING_PURPOSE,
      requirement: 'GEN-5.2.4-06',
    })
  }
}

/**
 * Validate a registration certificate payload against the schema and semantic rules.
 *
 * @param accessCertificateSub Required subject from the presented access certificate.
 */
export function validateRegistrationCertificatePayload(
  payload: unknown,
  accessCertificateSub: string
): ValidationResult {
  const result = parseRegistrationCertificateSchema(
    zRegistrationCertificatePayload,
    normalizeRegistrationCertificatePayload(payload)
  )

  if (!result.success) {
    return toValidationResult(result.issues)
  }

  // Additional semantic validations
  const validPayload: RegistrationCertificatePayload = result.data
  const issues = new ValidationIssues<RegistrationCertificateValidationCode>()

  validateEntitlementRequirements(validPayload, issues)

  // Validate subject identifier format (semantic identifier)
  const subResult = validateSemanticIdentifier(validPayload.sub)
  if (!subResult.valid) {
    issues.add({
      path: ['sub'],
      message: subResult.message,
      code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.INVALID_SEMANTIC_IDENTIFIER,
    })
  } else if (subResult.unknownPrefix) {
    issues.add({
      severity: 'warning',
      path: ['sub'],
      message: `Unknown semantic identifier initial characters: ${subResult.unknownPrefix}. This may be a national scheme (ETSI EN 319 412-1).`,
      code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.UNKNOWN_IDENTIFIER_PREFIX,
    })
  }

  // GEN-5.2.4-08: exp must be at most 12 months after iat
  if (typeof validPayload.exp === 'number') {
    const maxExp = secondsToDate(validPayload.iat)
    maxExp.setUTCFullYear(maxExp.getUTCFullYear() + 1)
    if (secondsToDate(validPayload.exp) > maxExp) {
      issues.add({
        path: ['exp'],
        message: 'exp must be at most 12 months after iat (GEN-5.2.4-08)',
        code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.EXP_TOO_LATE,
        requirement: 'GEN-5.2.4-08',
      })
    }
    if (validPayload.exp <= validPayload.iat) {
      issues.add({
        path: ['exp'],
        message: 'exp must be after iat',
        code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.EXPIRES_BEFORE_ISSUED,
        context: { issuedAt: secondsToDate(validPayload.iat), expiresAt: secondsToDate(validPayload.exp) },
      })
    }
  }

  // The intermediary identity replaces the registration certificate subject for this cross-certificate check.
  const expectedAccessCertificateSub = validPayload.intermediary?.sub ?? validPayload.sub
  const identityPath = validPayload.intermediary ? ['intermediary', 'sub'] : ['sub']
  if (accessCertificateSub !== expectedAccessCertificateSub) {
    issues.add({
      path: identityPath,
      message: `${validPayload.intermediary ? 'intermediary.sub' : 'sub'} must match the access certificate subject`,
      code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.ACCESS_CERTIFICATE_IDENTITY_MISMATCH,
    })
  }

  return issues.result()
}

/**
 * Validate a JWT header for registration certificate
 */
export function validateRegistrationCertificateJWTHeader(header: unknown): ValidationResult {
  const result = parseRegistrationCertificateSchema(zRegistrationCertificateJWTHeader, header)
  return toValidationResult(result.success ? [] : result.issues)
}

/**
 * Validate a complete registration certificate (header + payload)
 */
export function validateRegistrationCertificate(
  header: unknown,
  payload: unknown,
  accessCertificateSub: string
): ValidationResult {
  const headerResult = validateRegistrationCertificateJWTHeader(header)
  const payloadResult = validateRegistrationCertificatePayload(payload, accessCertificateSub)

  return toValidationResult([
    ...prefixIssuePaths('header', headerResult.issues),
    ...prefixIssuePaths('payload', payloadResult.issues),
  ])
}

// ============================================================================
// Subject Type Validation
// ============================================================================

/**
 * Check if payload represents a legal person
 */
export function isLegalPersonRegistrationCertificate(payload: RegistrationCertificatePayload): boolean {
  return typeof payload.sub_ln === 'string' && payload.sub_ln.length > 0
}

/**
 * Check if payload represents a natural person
 */
export function isNaturalPersonRegistrationCertificate(payload: RegistrationCertificatePayload): boolean {
  return (
    typeof payload.sub_gn === 'string' &&
    payload.sub_gn.length > 0 &&
    typeof payload.sub_fn === 'string' &&
    payload.sub_fn.length > 0
  )
}

/**
 * Validate as legal person registration certificate
 */
export function validateLegalPersonRegistrationCertificate(payload: unknown): ValidationResult {
  const result = parseRegistrationCertificateSchema(
    zLegalPersonSubject,
    normalizeRegistrationCertificatePayload(payload)
  )

  if (!result.success) {
    return toValidationResult(result.issues)
  }

  // Additional validation for legal person identifier format
  const issues = new ValidationIssues<RegistrationCertificateValidationCode>()
  const sub: string = result.data.sub
  // Legal person identifiers should follow ETSI EN 319 412-1 clause 5.1.4
  // Format: 3-character prefix (or national scheme `XX:`) + 2-letter country code + hyphen + identifier
  if (!/^(?:[A-Z]{3}|[A-Z]{2}:)[A-Z]{2}-.+$/.test(sub)) {
    issues.add({
      severity: 'warning',
      path: ['sub'],
      message:
        'Legal person identifier should follow format: PREFIX + COUNTRY + "-" + ID (e.g., "LEIXG-529900T8BM49AURSDO55")',
      code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.IDENTIFIER_FORMAT_WARNING,
    })
  }

  return issues.result()
}

/**
 * Validate as natural person registration certificate
 */
export function validateNaturalPersonRegistrationCertificate(payload: unknown): ValidationResult {
  const result = parseRegistrationCertificateSchema(
    zNaturalPersonSubject,
    normalizeRegistrationCertificatePayload(payload)
  )

  if (!result.success) {
    return toValidationResult(result.issues)
  }

  // Additional validation for natural person identifier format
  const issues = new ValidationIssues<RegistrationCertificateValidationCode>()
  const sub: string = result.data.sub
  // Natural person identifiers should follow ETSI EN 319 412-1 clause 5.1.3
  // Format: 3-character prefix (or national scheme `XX:`) + 2-letter country code + hyphen + identifier
  if (!/^(?:[A-Z]{3}|[A-Z]{2}:)[A-Z]{2}-.+$/.test(sub)) {
    issues.add({
      severity: 'warning',
      path: ['sub'],
      message:
        'Natural person identifier should follow format: PREFIX + COUNTRY + "-" + ID (e.g., "TINIT-RSSMRA85T10A562S")',
      code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.IDENTIFIER_FORMAT_WARNING,
    })
  }

  return issues.result()
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
  // Format: PREFIX (3 chars, or 2 letters + ":" for a national scheme, EN 319 412-1 LEG-5.1.4-03 (7)
  // and NAT-5.1.3-03 (7)) + COUNTRY (2 chars) + "-" + ID
  const match = identifier.match(/^([A-Z]{3}|[A-Z]{2}:)([A-Z]{2})-(.+)$/)

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
 * Assert that a registration certificate payload is valid, throws RegistrationCertificateError if not
 */
export function assertValidRegistrationCertificatePayload(
  payload: unknown,
  accessCertificateSub: string
): asserts payload is RegistrationCertificatePayload {
  const result = validateRegistrationCertificatePayload(payload, accessCertificateSub)
  if (!result.valid)
    throw new RegistrationCertificateValidationError('Invalid registration certificate payload', result.issues)
}

/**
 * Parse a registration certificate payload into its canonical form, accepting either dialect spelling.
 *
 * @throws RegistrationCertificateError if the payload is invalid
 */
export function parseRegistrationCertificatePayload(
  payload: unknown,
  accessCertificateSub: string
): RegistrationCertificatePayload {
  assertValidRegistrationCertificatePayload(payload, accessCertificateSub)
  return zRegistrationCertificatePayload.parse(normalizeRegistrationCertificatePayload(payload))
}

/**
 * Assert that a registration certificate is valid (header + payload), throws RegistrationCertificateError if not
 */
export function assertValidRegistrationCertificate(
  header: unknown,
  payload: unknown,
  accessCertificateSub: string
): void {
  const result = validateRegistrationCertificate(header, payload, accessCertificateSub)
  if (!result.valid) throw new RegistrationCertificateValidationError('Invalid registration certificate', result.issues)
}
