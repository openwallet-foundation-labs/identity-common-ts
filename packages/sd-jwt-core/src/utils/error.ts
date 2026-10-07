import type {
  JwtTimeClaimErrorCode,
  JwtTimeClaimErrorDetails,
  VerificationErrorCode,
} from '../types/verification-error'

export interface SDJWTExceptionOptions {
  /**
   * Additional information about the failure, for example the values a failed check compared.
   */
  details?: unknown

  /**
   * Machine-readable reason, set for failures that callers commonly need to tell apart (for example
   * an expired JWT), so they do not have to parse the message.
   */
  code?: VerificationErrorCode

  /**
   * The error that caused this one.
   */
  cause?: unknown
}

export class SDJWTException extends Error {
  public details?: unknown

  /**
   * Machine-readable reason, set for failures that callers commonly need to tell apart (for example
   * an expired JWT), so they do not have to parse the message.
   */
  public code?: VerificationErrorCode

  /**
   * The error that caused this one, when there is one.
   */
  public cause?: unknown

  constructor(message: string, options: SDJWTExceptionOptions = {}) {
    super(message)
    Object.setPrototypeOf(this, SDJWTException.prototype)
    this.name = 'SDJWTException'
    this.details = options.details
    this.code = options.code
    if (options.cause !== undefined) this.cause = options.cause
  }

  getFullMessage(): string {
    return `${this.name}: ${this.message} ${this.details ? `- ${JSON.stringify(this.details)}` : ''}`
  }
}

/**
 * Thrown when an `iat`, `nbf`, `exp` or maximum age check fails. `details` holds the values the
 * check compared: a token a few seconds past the allowed skew points to clock drift, one far past
 * it to an expired or stale token.
 */
export class JwtTimeClaimException extends SDJWTException {
  declare details: JwtTimeClaimErrorDetails
  declare code: JwtTimeClaimErrorCode

  constructor(
    message: string,
    options: SDJWTExceptionOptions & { details: JwtTimeClaimErrorDetails; code: JwtTimeClaimErrorCode }
  ) {
    super(message, options)
    Object.setPrototypeOf(this, JwtTimeClaimException.prototype)
    this.name = 'JwtTimeClaimException'
  }
}

/**
 * Narrows an unknown caught value to an Error instance.
 */
export function ensureError(value: unknown): Error {
  if (value instanceof Error) return value
  if (typeof value === 'string') return new Error(value)
  return new Error(String(value))
}
