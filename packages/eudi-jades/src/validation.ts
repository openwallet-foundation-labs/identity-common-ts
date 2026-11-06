/** Validation codes and issues of ETSI TS 119 182-1 V1.2.1 JAdES signatures. */
import {
  addValidationIssue,
  type SchemaValidationCode,
  VALIDATION_CODES,
  type ValidationIssueOf,
  type ValidationResult,
} from '@owf/identity-common'

/**
 * Codes of the JAdES checks that the schema codes of `@owf/identity-common` do not cover, so a caller can branch on a
 * failure rather than on the message text.
 */
export const JADES_VALIDATION_CODES = {
  /** No reference to the signing certificate: `x5t#S256`, `x5c`, `x5t#o` or `sigX5ts` */
  MISSING_CERTIFICATE_REFERENCE: 'missing_certificate_reference',
  /** A baseline time-stamp that is not a single RFC 3161 token in `val` */
  INVALID_TIMESTAMP: 'invalid_timestamp',
  /** Validation data a B-LT or B-LTA signature requires is not evidenced */
  MISSING_VALIDATION_DATA: 'missing_validation_data',
  /**
   * The shared `invalid_crit` of `VALIDATION_CODES`, listed so the schemas can use it: a `crit` that is not unique, names
   * an absent or registered parameter, or lacks `sigD` or `b64`
   */
  INVALID_CRIT: VALIDATION_CODES.INVALID_CRIT,
} as const

/** A JAdES validation code */
export type JadesValidationCode = (typeof JADES_VALIDATION_CODES)[keyof typeof JADES_VALIDATION_CODES]

/** An issue of a JAdES validation, with a code of `JADES_VALIDATION_CODES` or of `SCHEMA_VALIDATION_CODES` */
export type JadesValidationIssue = ValidationIssueOf<JadesValidationCode | SchemaValidationCode>

/** The result of a JAdES validation */
export type JadesValidationResult = ValidationResult<JadesValidationIssue>

/** `addValidationIssue` for the codes of a JAdES validation */
export const addJadesIssue = addValidationIssue<JadesValidationCode | SchemaValidationCode>
