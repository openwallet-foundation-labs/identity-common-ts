import { decodeJwt, verifyJwt } from '@owf/jose'
import type { CallbackContext } from '../callbacks'
import { extractJwkFromJwksForJwt } from '../common/jwk/jwks'
import { Oauth2Error } from '../error/Oauth2Error'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'
import { fetchJwks } from '../metadata/fetch-jwks-uri'
import { zIdTokenJwtHeader, zIdTokenJwtPayload } from './z-id-token-jwt'

export interface VerifyIdTokenJwtOptions {
  /**
   * The compact id token.
   */
  idToken: string

  /**
   * Callbacks used for verifying the id token
   */
  callbacks: Pick<CallbackContext, 'verifyJws' | 'fetch' | 'fetchLimits' | 'getJwks'>

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
   * Authorization server metadata
   */
  authorizationServer: AuthorizationServerMetadata

  /**
   * The client_id of the Relying Party for which the token was issued.
   */
  clientId: string

  /**
   * Expected nonce in the payload. If not provided the nonce won't be validated.
   */
  expectedNonce?: string
}

/**
 * Verify an ID Token JWT.
 */
export async function verifyIdTokenJwt(options: VerifyIdTokenJwtOptions) {
  const decodedJwt = decodeJwt({
    jwt: options.idToken,
    headerSchema: zIdTokenJwtHeader,
    payloadSchema: zIdTokenJwtPayload,
  })
  const { header, payload } = decodedJwt

  const jwksUrl = options.authorizationServer.jwks_uri
  if (!jwksUrl) {
    throw new Oauth2Error(
      `Authorization server '${options.authorizationServer.issuer}' does not have a 'jwks_uri' parameter to fetch JWKs.`
    )
  }

  if (payload.iss !== options.authorizationServer.issuer) {
    throw new Oauth2Error(
      `Invalid 'iss' claim in id token jwt. Expected '${options.authorizationServer.issuer}', got '${payload.iss}'.`
    )
  }

  if (payload.azp && payload.azp !== options.clientId) {
    throw new Oauth2Error(`Invalid 'azp' claim in id token jwt. Expected '${options.clientId}', got '${payload.azp}'.`)
  }

  const jwks = await fetchJwks(jwksUrl, options.callbacks)
  const publicJwk = extractJwkFromJwksForJwt({
    kid: header.kid,
    jwks,
    use: 'sig',
  })

  await verifyJwt({
    jwt: decodedJwt,
    signer: { method: 'jwk', publicJwk, alg: header.alg },
    verifyJwsCallback: options.callbacks.verifyJws,
    errorMessage: 'Error during verification of id token jwt.',
    now: options.now,
    skewSeconds: options.allowedSkewInSeconds,
    expectedAudience: options.clientId,
    expectedIssuer: options.authorizationServer.issuer,
    expectedNonce: options.expectedNonce,
  })

  return {
    header,
    payload,
  }
}
