import type { JwtTimeClaimErrorCode, JwtTimeClaimErrorDetails } from './types'
import { JwtTimeClaimException } from './utils'

/** The JWT a payload check runs on. It names the JWT in error messages and selects the error codes. */
export type JwtRole = 'jwt' | 'key-binding-jwt'

type TimeClaimFailure = 'notYetValid' | 'expired' | 'tooOld'

const TIME_CLAIM_ERRORS: Record<JwtRole, { name: string } & Record<TimeClaimFailure, JwtTimeClaimErrorCode>> = {
  jwt: { name: 'JWT', notYetValid: 'JWT_NOT_YET_VALID', expired: 'JWT_EXPIRED', tooOld: 'JWT_TOO_OLD' },
  'key-binding-jwt': {
    name: 'Key Binding JWT',
    notYetValid: 'KEY_BINDING_JWT_NOT_YET_VALID',
    expired: 'KEY_BINDING_JWT_EXPIRED',
    tooOld: 'KEY_BINDING_JWT_TOO_OLD',
  },
}

const PROBLEMS: Record<TimeClaimFailure, string> = {
  notYetValid: 'is not yet valid',
  expired: 'is expired',
  tooOld: 'is too old',
}

/** The exception for a failed `iat`, `nbf`, `exp` or maximum age check of the given JWT. */
export const timeClaimException = (
  role: JwtRole,
  failure: TimeClaimFailure,
  details: JwtTimeClaimErrorDetails
): JwtTimeClaimException => {
  const errors = TIME_CLAIM_ERRORS[role]
  return new JwtTimeClaimException(`Verify Error: ${errors.name} ${PROBLEMS[failure]}`, {
    details,
    code: errors[failure],
  })
}
