import { decodeJwt, verifyJwt } from '@owf/jose'
import type { CallbackContext } from '../callbacks'
import { extractJwkFromJwksForJwt } from '../common/jwk/jwks'
import { Oauth2Error } from '../error/Oauth2Error'
import { resolveAuthorizationServerMetadata } from '../metadata/authorization-server/authorization-server-metadata'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'
import { fetchJwks } from '../metadata/fetch-jwks-uri'
import { zAccessTokenProfileJwtHeader, zAccessTokenProfileJwtPayload } from './z-access-token-jwt'

export enum SupportedAuthenticationScheme {
  Bearer = 'Bearer',
  DPoP = 'DPoP',
}

export interface VerifyJwtProfileAccessTokenOptions {
  /**
   * The access token
   */
  accessToken: string

  /**
   * Callbacks used for verifying the access token
   */
  callbacks: Pick<CallbackContext, 'verifyJws' | 'fetch' | 'fetchLimits' | 'getJwks' | 'getAuthorizationServerMetadata'>

  /**
   * If not provided current time will be used
   */
  now?: Date

  /**
   * Allowed clock skew in seconds for the `exp`, `nbf` and `iat` checks.
   *
   * @default 30
   */
  allowedSkewInSeconds?: number

  /**
   * Identifier of the resource server
   */
  resourceServer: string

  /**
   * The authorization servers that this resource endpoint supports, as metadata or issuer identifier. Only the
   * authorization server whose issuer identifier is the `iss` of the access token is resolved, with the
   * `getAuthorizationServerMetadata` callback or else over HTTP.
   */
  authorizationServers: Array<AuthorizationServerMetadata | string>
}

/**
 * Verify an access token as a JWT Profile access token.
 *
 * @throws {@link ValidationError} if the JWT header or payload does not align with JWT Profile rules
 * @throws {@link JoseParseError} if the jwt is not a valid jwt format, or the jwt header/payload cannot be parsed as JSON
 * @throws {@link JoseVerificationError} if the signature does not verify
 * @throws {@link JoseValidationError} if a claim does not verify, e.g. an expired token or one for another audience
 */
export async function verifyJwtProfileAccessToken(options: VerifyJwtProfileAccessTokenOptions) {
  const decodedJwt = decodeJwt({
    jwt: options.accessToken,
    headerSchema: zAccessTokenProfileJwtHeader,
    payloadSchema: zAccessTokenProfileJwtPayload,
  })

  const listedAuthorizationServer = options.authorizationServers.find(
    (authorizationServer) =>
      (typeof authorizationServer === 'string' ? authorizationServer : authorizationServer.issuer) ===
      decodedJwt.payload.iss
  )
  if (!listedAuthorizationServer) {
    // Authorization server not found
    throw new Oauth2Error(
      `Access token jwt contains unrecognized authorization server 'iss' value of '${decodedJwt.payload.iss}'`
    )
  }

  const authorizationServer = await resolveAuthorizationServerMetadata(listedAuthorizationServer, options.callbacks)
  const jwksUrl = authorizationServer.jwks_uri
  if (!jwksUrl) {
    throw new Oauth2Error(
      `Authorization server '${authorizationServer.issuer}' does not have a 'jwks_uri' parameter to fetch JWKs.`
    )
  }

  const jwks = await fetchJwks(jwksUrl, options.callbacks, { kid: decodedJwt.header.kid })
  const publicJwk = extractJwkFromJwksForJwt({
    kid: decodedJwt.header.kid,
    jwks,
    use: 'sig',
  })

  await verifyJwt({
    jwt: decodedJwt,
    signer: { method: 'jwk', publicJwk, alg: decodedJwt.header.alg },
    verifyJwsCallback: options.callbacks.verifyJws,
    errorMessage: 'Error during verification of access token jwt.',
    now: options.now,
    skewSeconds: options.allowedSkewInSeconds,
    expectedAudience: options.resourceServer,
  })

  return {
    header: decodedJwt.header,
    payload: decodedJwt.payload,
    authorizationServer,
  }
}
