import type { JwtTimeClaimErrorDetails, VerificationErrorCode } from './types'
import { SDJWTException } from './utils'

/** The JWT a payload check runs on. It names the JWT in error messages and selects the error codes. */
export type JwtRole = 'jwt' | 'key-binding-jwt'

const TIME_CLAIM_ERRORS: Record<
  JwtRole,
  { name: string; notYetValid: VerificationErrorCode; expired: VerificationErrorCode; tooOld: VerificationErrorCode }
> = {
  jwt: { name: 'JWT', notYetValid: 'JWT_NOT_YET_VALID', expired: 'JWT_EXPIRED', tooOld: 'JWT_TOO_OLD' },
  'key-binding-jwt': {
    name: 'Key Binding JWT',
    notYetValid: 'KEY_BINDING_JWT_NOT_YET_VALID',
    expired: 'KEY_BINDING_JWT_EXPIRED',
    tooOld: 'KEY_BINDING_JWT_TOO_OLD',
  },
}

const formatNumericDate = (seconds: number) => {
  const date = new Date(seconds * 1000)
  // Far-future values are finite numbers but outside the range a Date can represent.
  return Number.isNaN(date.getTime()) ? String(seconds) : date.toISOString()
}

const formatSeconds = (seconds: number) => `${Math.round(seconds * 1000) / 1000}s`

/**
 * The exception for a failed `iat`, `nbf`, `exp` or maximum age check. The message carries the
 * claim, the current time and the allowed skew, so a log line tells clock drift (a few seconds
 * over) apart from a stale token (far over).
 */
export const timeClaimException = (
  role: JwtRole,
  failure: 'notYetValid' | 'expired' | 'tooOld',
  details: JwtTimeClaimErrorDetails
): SDJWTException => {
  const errors = TIME_CLAIM_ERRORS[role]
  const { claim, value, currentDate, skewSeconds, maxAgeSeconds } = details
  const problem = {
    notYetValid: 'is not yet valid',
    expired: 'is expired',
    tooOld: 'is too old',
  }[failure]
  const distance =
    failure === 'tooOld'
      ? `age ${formatSeconds(currentDate - value)}, maximum age ${formatSeconds(maxAgeSeconds ?? 0)}`
      : failure === 'expired'
        ? `${formatSeconds(currentDate - value)} after ${claim}`
        : `${formatSeconds(value - currentDate)} before ${claim}`

  return new SDJWTException(
    `Verify Error: ${errors.name} ${problem}: ${claim} is ${formatNumericDate(value)}, current time is ${formatNumericDate(currentDate)} (${distance}, allowed clock skew ${formatSeconds(skewSeconds)})`,
    details,
    errors[failure]
  )
}
