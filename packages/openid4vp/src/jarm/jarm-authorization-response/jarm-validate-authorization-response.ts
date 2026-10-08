import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { JoseClaimVerificationError, verifyJwtClaims } from '@owf/jose'
import {
  type JarmAuthorizationResponse,
  type JarmAuthorizationResponseEncryptedOnly,
  zJarmAuthorizationResponse,
} from './z-jarm-authorization-response'

export const jarmAuthorizationResponseValidate = (options: {
  expectedClientId: string
  authorizationResponse: JarmAuthorizationResponse | JarmAuthorizationResponseEncryptedOnly
}) => {
  const { expectedClientId, authorizationResponse } = options

  // The traditional Jarm Validation Methods do not account for the encrypted response.
  if (!zJarmAuthorizationResponse.safeParse(authorizationResponse).success) {
    return
  }

  // 3. The client obtains the aud element from the JWT and checks whether it matches the client id the client used to identify itself in the corresponding authorization request. If the check fails, the client MUST abort processing and refuse the response.
  if (
    (Array.isArray(authorizationResponse.aud) && !authorizationResponse.aud.includes(expectedClientId)) ||
    (typeof authorizationResponse.aud === 'string' && authorizationResponse.aud !== expectedClientId)
  ) {
    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Invalid 'aud' claim in the JARM authorization response.`,
      },
      {
        internalMessage: `Invalid 'aud' claim in JARM authorization response. Expected '${
          expectedClientId
        }' received '${JSON.stringify(authorizationResponse.aud)}'.`,
      }
    )
  }

  // 4. The client checks the JWT's exp element to determine if the JWT is still valid. If the check fails, the client MUST abort processing and refuse the response.
  // The time claims are verified the way they are for every other JWT: `exp`, `nbf` and `iat`, with
  // the default clock skew of 30 seconds.
  try {
    verifyJwtClaims(authorizationResponse)
  } catch (error) {
    if (!(error instanceof JoseClaimVerificationError)) throw error

    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description:
          error.reason === 'expired'
            ? 'The JARM authorization response is expired.'
            : error.reason === 'not-yet-valid'
              ? 'The JARM authorization response is not yet valid.'
              : `Invalid '${error.claim}' claim in the JARM authorization response.`,
      },
      { cause: error }
    )
  }
}
