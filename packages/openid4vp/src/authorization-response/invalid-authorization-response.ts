import { Oauth2Error, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { JsonParseError } from '@openid4vc/utils'
import { IdentityError, ValidationError } from '@owf/identity-common'
import { JoseInvalidArgumentError } from '@owf/jose'

/**
 * Throws the error of an authorization response that cannot be parsed or verified as an `invalid_request` error
 * response, with the error as `cause`.
 *
 * An `Oauth2Error`, such as the authorization error response of the wallet, an invalid option of the verifier and an
 * error that is not an `IdentityError`, such as most errors of a callback, are thrown as is.
 */
export function throwAsInvalidAuthorizationResponse(error: unknown, errorDescription: string): never {
  if (!(error instanceof IdentityError) || error instanceof Oauth2Error || error instanceof JoseInvalidArgumentError) {
    throw error
  }

  throw new Oauth2ServerErrorResponseError(
    {
      error: Oauth2ErrorCodes.InvalidRequest,
      // Only the first line of a validation error is our own message: the issues below it name keys of the response,
      // and the message of other errors can contain the response itself, such as the decrypted payload
      error_description: error instanceof ValidationError ? error.message.split('\n')[0] : errorDescription,
    },
    // The verifier keeps the whole message, except the decrypted payload in the message of a JsonParseError
    { cause: error, internalMessage: error instanceof JsonParseError ? errorDescription : error.message }
  )
}
