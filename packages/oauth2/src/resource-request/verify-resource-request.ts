import { Openid4vcBaseError } from '@openid4vc/utils'
import { IdentityError, ValidationError } from '@owf/identity-common'
import { decodeJwt, JoseInvalidArgumentError, JoseParseError, type Jwk } from '@owf/jose'
import { introspectToken } from '../access-token/introspect-token'
import { SupportedAuthenticationScheme, verifyJwtProfileAccessToken } from '../access-token/verify-access-token'
import {
  type AccessTokenProfileJwtPayload,
  zAccessTokenProfileJwtHeader,
  zAccessTokenProfileJwtPayload,
} from '../access-token/z-access-token-jwt'
import type { TokenIntrospectionResponse } from '../access-token/z-token-introspection'
import type { CallbackContext } from '../callbacks'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { type DpopVerificationOptions, extractDpopJwtFromHeaders, verifyDpopJwt } from '../dpop/dpop'
import { Oauth2Error } from '../error/Oauth2Error'
import { Oauth2ResourceUnauthorizedError } from '../error/Oauth2ResourceUnauthorizedError'
import {
  isAuthorizationServerMetadata,
  resolveAuthorizationServerMetadata,
} from '../metadata/authorization-server/authorization-server-metadata'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'

export interface VerifyResourceRequestOptions {
  /**
   * The incoming request
   */
  request: RequestLike

  /**
   * Identifier for the resource server, will be matched with the `aud` value of the access token.
   */
  resourceServer: string

  /**
   * Callbacks for verification of the access token.
   */
  callbacks: Pick<
    CallbackContext,
    | 'verifyJws'
    | 'hash'
    | 'clientAuthentication'
    | 'fetch'
    | 'fetchLimits'
    | 'getJwks'
    | 'getAuthorizationServerMetadata'
  >

  /**
   * allowed auth schemes for the access token. If not provided
   * all supported authentication schemes are allowed.
   */
  allowedAuthenticationSchemes?: SupportedAuthenticationScheme[]

  /**
   * The authorization servers that this resource endpoint supports, as metadata or as `{ issuer, allowIntrospection }`.
   * The latter is resolved only when needed, with the `getAuthorizationServerMetadata` callback or else over HTTP:
   * for a JWT access token only the authorization server of its `iss`, for an opaque access token one at a time,
   * in order, until one reports it as active through token introspection.
   *
   * An opaque access token is only introspected at an authorization server whose metadata has an
   * `introspection_endpoint`. One given with `allowIntrospection: false` is skipped without resolving its metadata.
   * When no authorization server allows introspection, opaque access tokens are rejected.
   *
   * The order matters for opaque access tokens: each authorization server before the one that issued the token
   * costs a metadata resolution and an introspection request, and the first one that reports the token as active is
   * the one it is accepted for. Try to filter the list of authorization servers before passing it, and list the authorization server that issues most opaque access tokens first.
   */
  authorizationServers: Array<AuthorizationServerMetadata | { issuer: string; allowIntrospection: boolean }>

  /**
   * Additional DPoP verification options.
   */
  dpop?: DpopVerificationOptions

  now?: Date

  /**
   * Allowed clock skew in seconds for the `exp`, `nbf` and `iat` checks of the access token and the
   * DPoP proof. A `dpop.allowedSkewInSeconds` takes precedence for the DPoP proof.
   *
   * @default 30
   */
  allowedSkewInSeconds?: number
}

export async function verifyResourceRequest(options: VerifyResourceRequestOptions) {
  const allowedAuthenticationSchemes =
    options.allowedAuthenticationSchemes ?? Object.values(SupportedAuthenticationScheme)
  if (allowedAuthenticationSchemes.length === 0) {
    throw new Oauth2Error(
      `Empty array provided for 'allowedAuthenticationSchemes', provide at least one allowed authentication scheme, or remove the value to allow all supported authentication schemes`
    )
  }

  const authorizationHeader = options.request.headers.get('Authorization')
  if (!authorizationHeader) {
    throw new Oauth2ResourceUnauthorizedError(
      `No 'Authorization' header provided in request.`,
      allowedAuthenticationSchemes.map((scheme) => ({ scheme }))
    )
  }

  const [providedScheme, accessToken] = authorizationHeader.split(' ', 2)
  if (!providedScheme || !accessToken) {
    throw new Oauth2ResourceUnauthorizedError(
      `Malformed 'Authorization' header provided in request.`,
      allowedAuthenticationSchemes.map((scheme) => ({ scheme }))
    )
  }

  // RFC 9110 §11.1: the auth-scheme is case-insensitive, so resolve it to its canonical form
  const scheme = allowedAuthenticationSchemes.find(
    (allowedScheme) => allowedScheme.toLowerCase() === providedScheme.toLowerCase()
  )
  if (!scheme || (scheme !== SupportedAuthenticationScheme.Bearer && scheme !== SupportedAuthenticationScheme.DPoP)) {
    throw new Oauth2ResourceUnauthorizedError(
      `Provided authentication scheme '${providedScheme}' is not allowed. Allowed authentication schemes are ${allowedAuthenticationSchemes.map((s) => `'${s}'`).join(', ')}.`,
      allowedAuthenticationSchemes.map((scheme) => ({ scheme }))
    )
  }

  // A token that is not a jwt profile access token is probably an opaque token, which is introspected below.
  // One that is must verify: an expired one, or one for another resource server, does not get to be introspected.
  const verificationResult = isOpaqueAccessToken(accessToken)
    ? null
    : await verifyJwtProfileAccessToken({
        accessToken,
        callbacks: options.callbacks,
        authorizationServers: options.authorizationServers,
        resourceServer: options.resourceServer,
        now: options.now,
        allowedSkewInSeconds: options.allowedSkewInSeconds,
      }).catch((error) => {
        if (error instanceof JoseInvalidArgumentError) throw error
        // The message of an error raised while fetching from the authorization server, such as its JWKS,
        // holds what that server responded with, which is not for the client: it gets a generic description
        const errorMessage =
          error instanceof IdentityError && !(error instanceof Openid4vcBaseError)
            ? error.message
            : 'Invalid access token'
        throw new Oauth2ResourceUnauthorizedError(
          `Error occurred during verification of jwt profile access token: ${error.message}`,
          {
            scheme,
            error: Oauth2ErrorCodes.InvalidToken,
            error_description: errorMessage,
          },
          { cause: error }
        )
      })

  let tokenPayload: AccessTokenProfileJwtPayload | TokenIntrospectionResponse | undefined = verificationResult?.payload
  let authorizationServer = verificationResult?.authorizationServer
  if (!tokenPayload) {
    // If there's no verification result it means it couldn't be parsed and we will try
    // to use token introspection on all authorization servers until we've found the correct one
    for (const listedAuthorizationServer of options.authorizationServers) {
      if (!isAuthorizationServerMetadata(listedAuthorizationServer) && !listedAuthorizationServer.allowIntrospection) {
        continue
      }

      try {
        const authorizationServerMetadata = await resolveAuthorizationServerMetadata(
          listedAuthorizationServer,
          options.callbacks
        )
        const introspectionResult = await introspectToken({
          authorizationServerMetadata,
          callbacks: options.callbacks,
          token: accessToken,
          tokenTypeHint: scheme,
        })

        // An inactive token is revoked, expired or unknown to this authorization server (RFC 7662 §2.2)
        if (!introspectionResult.active) continue

        tokenPayload = introspectionResult
        authorizationServer = authorizationServerMetadata
        break
      } catch (_error) {
        // No-op?
      }
    }
  }

  if (!tokenPayload || !authorizationServer) {
    throw new Oauth2ResourceUnauthorizedError('Could not verify token as jwt or using token introspection.', {
      scheme,
      error: Oauth2ErrorCodes.InvalidToken,
      error_description: 'Token is not valid',
    })
  }

  let dpopJwk: Jwk | undefined
  if (
    scheme === SupportedAuthenticationScheme.DPoP ||
    // two alternative methods to determine whether DPoP was used. As the user can
    // choose to include `Bearer` scheme even if DPoP was used
    tokenPayload.token_type === SupportedAuthenticationScheme.DPoP ||
    tokenPayload.cnf?.jkt
  ) {
    const dpopJwtResult = extractDpopJwtFromHeaders(options.request.headers)
    if (!dpopJwtResult.valid) {
      throw new Oauth2ResourceUnauthorizedError(
        `Request contains a 'DPoP' header, but the value is not a valid DPoP jwt.`,
        {
          scheme,
          error: Oauth2ErrorCodes.InvalidDpopProof,
          error_description: `Request contains a 'DPoP' header, but the value is not a valid DPoP jwt.`,
        }
      )
    }

    if (!dpopJwtResult.dpopJwt) {
      throw new Oauth2ResourceUnauthorizedError(`Request is missing required 'DPoP' header.`, {
        scheme,
        error: Oauth2ErrorCodes.InvalidDpopProof,
        error_description: `Request is missing required 'DPoP' header.`,
      })
    }

    // Take the jwk thumbprint from the token / introspection result
    if (!tokenPayload.cnf?.jkt) {
      throw new Oauth2ResourceUnauthorizedError(
        `Token payload is missing required 'cnf.jkt' value for DPoP verification.`,
        {
          scheme,
          error: Oauth2ErrorCodes.InvalidToken,
          error_description: `Token payload is missing required 'cnf.jkt' value for DPoP verification.`,
        }
      )
    }

    try {
      const decodedDpopJwt = await verifyDpopJwt({
        callbacks: options.callbacks,
        dpopJwt: dpopJwtResult.dpopJwt,
        request: options.request,
        accessToken,
        now: options.now,
        expectedJwkThumbprint: tokenPayload.cnf?.jkt,
        allowedSigningAlgs: authorizationServer.dpop_signing_alg_values_supported,
        expectedNonce: options.dpop?.expectedNonce,
        maxProofAgeSeconds: options.dpop?.maxProofAgeSeconds,
        allowedSkewInSeconds: options.dpop?.allowedSkewInSeconds ?? options.allowedSkewInSeconds,
        assertJtiUniqueness: options.dpop?.assertJtiUniqueness,
      })
      dpopJwk = decodedDpopJwt.header.jwk
    } catch (error) {
      if (error instanceof JoseInvalidArgumentError) throw error
      const errorMessage = error instanceof IdentityError ? error.message : 'Error verifying DPoP jwt'
      throw new Oauth2ResourceUnauthorizedError(
        `Error occurred during verification of jwt profile access token: ${error instanceof Error ? error.message : error}`,
        {
          scheme,
          error: Oauth2ErrorCodes.InvalidDpopProof,
          error_description: errorMessage,
        },
        { cause: error }
      )
    }
  }

  return {
    tokenPayload,
    dpop: dpopJwk ? { jwk: dpopJwk } : undefined,
    scheme,
    accessToken,
    authorizationServer: authorizationServer.issuer,
  }
}

/** Whether the access token does not decode as a JWT profile access token (RFC 9068) */
function isOpaqueAccessToken(accessToken: string) {
  try {
    decodeJwt({
      jwt: accessToken,
      headerSchema: zAccessTokenProfileJwtHeader,
      payloadSchema: zAccessTokenProfileJwtPayload,
    })
    return false
  } catch (error) {
    return error instanceof JoseParseError || error instanceof ValidationError
  }
}
