import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { JoseValidationError, verifyJwtClaims } from '@owf/jose'
import {
  type JarmAuthorizationResponse,
  type JarmAuthorizationResponseEncryptedOnly,
  zJarmAuthorizationResponse,
} from './z-jarm-authorization-response'

export const jarmAuthorizationResponseValidate = (options: {
  expectedClientId: string
  authorizationResponse: JarmAuthorizationResponse | JarmAuthorizationResponseEncryptedOnly
  now?: Date
  allowedSkewInSeconds?: number
}) => {
  const { expectedClientId, authorizationResponse } = options

  // The traditional Jarm Validation Methods do not account for the encrypted response.
  if (!zJarmAuthorizationResponse.safeParse(authorizationResponse).success) {
    return
  }

  // 3. The client obtains the aud element from the JWT and checks whether it matches the client id the client used to identify itself in the corresponding authorization request. If the check fails, the client MUST abort processing and refuse the response.
  // 4. The client checks the JWT's exp element to determine if the JWT is still valid. If the check fails, the client MUST abort processing and refuse the response.
  // The time claims are verified the way they are for every other JWT: `exp`, `nbf` and `iat`.
  try {
    verifyJwtClaims(authorizationResponse, {
      expectedAudience: expectedClientId,
      now: options.now,
      skewSeconds: options.allowedSkewInSeconds,
    })
  } catch (error) {
    if (!(error instanceof JoseValidationError)) throw error

    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: error.findIssue('expired')
          ? 'The JARM authorization response is expired.'
          : error.findIssue('not_yet_valid')
            ? 'The JARM authorization response is not yet valid.'
            : `Invalid '${error.issues[0]?.path[0]}' claim in the JARM authorization response.`,
      },
      { cause: error }
    )
  }
}
