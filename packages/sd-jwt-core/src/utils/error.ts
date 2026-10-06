import type {
  JwtTimeClaimErrorCode,
  JwtTimeClaimErrorDetails,
  VerificationErrorCode,
} from '../types/verification-error'

export class SDJWTException extends Error {
  public details?: unknown

  /**
   * Machine-readable reason, set for failures that callers commonly need to tell apart (for example
   * an expired JWT), so they do not have to parse the message.
   */
  public code?: VerificationErrorCode

  constructor(message: string, details?: unknown, code?: VerificationErrorCode) {
    super(message)
    Object.setPrototypeOf(this, SDJWTException.prototype)
    this.name = 'SDJWTException'
    this.details = details
    this.code = code
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

  constructor(message: string, details: JwtTimeClaimErrorDetails, code: JwtTimeClaimErrorCode) {
    super(message, details, code)
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
