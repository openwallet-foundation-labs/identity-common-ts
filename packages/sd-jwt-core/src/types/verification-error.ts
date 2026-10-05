/**
 * Error codes for SD-JWT verification errors.
 */
export type VerificationErrorCode =
  | 'HASHER_NOT_FOUND'
  | 'VERIFIER_NOT_FOUND'
  | 'INVALID_SD_JWT'
  | 'INVALID_JWT_FORMAT'
  | 'JWT_NOT_YET_VALID'
  | 'JWT_EXPIRED'
  | 'JWT_TOO_OLD'
  | 'INVALID_JWT_SIGNATURE'
  | 'INVALID_AUDIENCE'
  | 'INVALID_ISSUER'
  | 'INVALID_SUBJECT'
  | 'INVALID_VCT'
  | 'MISSING_REQUIRED_CLAIMS'
  | 'KEY_BINDING_JWT_MISSING'
  | 'KEY_BINDING_VERIFIER_NOT_FOUND'
  | 'KEY_BINDING_SIGNATURE_INVALID'
  | 'KEY_BINDING_SD_HASH_INVALID'
  | 'KEY_BINDING_JWT_NOT_YET_VALID'
  | 'KEY_BINDING_JWT_EXPIRED'
  | 'KEY_BINDING_JWT_TOO_OLD'
  | 'STATUS_VERIFICATION_FAILED'
  | 'STATUS_INVALID'
  | 'VCT_VERIFICATION_FAILED'
  | 'UNKNOWN_ERROR'

/**
 * Codes of a failed `iat`, `nbf`, `exp` or maximum age check, for the issuer-signed JWT and for the
 * Key Binding JWT.
 */
export type JwtTimeClaimErrorCode =
  | 'JWT_NOT_YET_VALID'
  | 'JWT_EXPIRED'
  | 'JWT_TOO_OLD'
  | 'KEY_BINDING_JWT_NOT_YET_VALID'
  | 'KEY_BINDING_JWT_EXPIRED'
  | 'KEY_BINDING_JWT_TOO_OLD'

/**
 * Represents a single verification error.
 */
export type VerificationError = {
  /**
   * The error code identifying the type of error.
   */
  code: VerificationErrorCode

  /**
   * Human-readable error message.
   */
  message: string

  /**
   * Optional additional details about the error.
   */
  details?: unknown
}

/**
 * Result type for safe verification that collects all errors.
 */
export type SafeVerifyResult<T> =
  | {
      success: true
      data: T
      errors?: never
    }
  | {
      success: false
      data?: never
      errors: VerificationError[]
    }

/**
 * The values a failed `iat`, `nbf`, `exp` or maximum age check compared, in the `details` of a
 * `JwtTimeClaimException`. Times are in seconds since the epoch.
 */
export type JwtTimeClaimErrorDetails = {
  /** The claim that failed the check. */
  claim: 'iat' | 'nbf' | 'exp'
  /** The claim value. */
  value: number
  /** The time the claim was compared against. */
  currentDate: number
  /** The clock skew that was allowed. */
  skewSeconds: number
  /** The maximum age, set when the JWT was rejected for being older than that. */
  maxAgeSeconds?: number
}
