import { IdentityError, ValidationError, type ValidationIssueOf } from '@owf/identity-common'

/**
 * StatusListError is a custom error class for Status List related errors.
 */
export class StatusListError extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    this.name = 'StatusListError'
  }
}

/** Codes for the checks of a status list and of the status of a Referenced Token in it */
export const STATUS_LIST_VALIDATION_CODES = {
  /** `lst` is not a status list compressed with zlib */
  INVALID_STATUS_LIST: 'invalid_status_list',
  /** The `idx` of a Referenced Token is not an index of the status list (Token Status List § 8.3) */
  INDEX_OUT_OF_RANGE: 'index_out_of_range',
  /** The status at the `idx` of a Referenced Token is not Valid, e.g. `1` for Invalid (revoked) */
  STATUS_NOT_VALID: 'status_not_valid',
} as const

/** A code of {@link STATUS_LIST_VALIDATION_CODES} */
export type StatusListValidationCode = (typeof STATUS_LIST_VALIDATION_CODES)[keyof typeof STATUS_LIST_VALIDATION_CODES]

/** The context of the issues with a code of {@link STATUS_LIST_VALIDATION_CODES} */
export interface StatusListValidationContexts {
  index_out_of_range: { idx: number; totalStatuses: number }
  status_not_valid: { idx: number; status: number }
}

/** An issue of a status list, or of the status of a Referenced Token in it */
export type StatusListValidationIssue = ValidationIssueOf<StatusListValidationCode, StatusListValidationContexts>

/**
 * Thrown when a status list cannot be decompressed, or does not give a Referenced Token a Valid status,
 * with the `issues` of the validation.
 */
export class StatusListValidationError extends ValidationError<StatusListValidationIssue> {}
