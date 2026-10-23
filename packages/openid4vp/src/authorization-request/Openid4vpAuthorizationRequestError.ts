import { Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import type { ParsedClientIdentifier } from '../client-identifier-prefix/parse-client-identifier-prefix'
import type { VerifiedJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import type { Openid4vpAuthorizationRequestPayload } from './z-authorization-request-payload'

/**
 * Error thrown when resolving an authorization request fails once the authorization request payload is known.
 * The wallet can answer it with an Authorization Error Response (OpenID4VP 1.0 Section 8.5) containing
 * `errorResponse`.
 *
 * `isClientAuthenticated` tells whether the client was authenticated: the JAR (if any) was verified and the
 * client identifier was validated, so the `response_uri` belongs to the client. When it is `false`, the
 * `response_uri` comes from a request that could not be verified, so a `redirect_uri` the response endpoint
 * returns should not be opened: it could send the user anywhere, in the name of any verifier.
 *
 * For the `openid_federation` client identifier prefix, the trust chain is verified outside this
 * library, so verify it before treating the client as authenticated.
 *
 * Failures before the payload is known (for example when fetching the request object) throw a plain
 * `Oauth2ServerErrorResponseError`, as there is nowhere to send the error to.
 */
export class Openid4vpAuthorizationRequestError extends Oauth2ServerErrorResponseError {
  public readonly authorizationRequestPayload: Openid4vpAuthorizationRequestPayload

  /**
   * Whether the client was authenticated. Only then is `client` defined.
   */
  public readonly isClientAuthenticated: boolean
  public readonly client: ParsedClientIdentifier | undefined
  public readonly jar: VerifiedJarRequest | undefined

  public constructor(
    error: Oauth2ServerErrorResponseError,
    request: Pick<Openid4vpAuthorizationRequestError, 'authorizationRequestPayload'> &
      Partial<Pick<Openid4vpAuthorizationRequestError, 'client' | 'jar'>>
  ) {
    super(error.errorResponse, { status: error.status, cause: error })
    this.message = error.message
    this.authorizationRequestPayload = request.authorizationRequestPayload
    this.isClientAuthenticated = request.client !== undefined
    this.client = request.client
    this.jar = request.jar
  }
}
