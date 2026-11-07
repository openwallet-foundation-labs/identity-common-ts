import {
  type CallbackContext,
  type CreateJarAuthorizationRequestOptions,
  createJarAuthorizationRequest,
  Oauth2ErrorCodes,
  Oauth2ServerErrorResponseError,
} from '@openid4vc/oauth2'
import { objectToQueryParams, URL, URLSearchParams } from '@openid4vc/utils'
import { parseWithErrorHandling } from '@owf/identity-common'
import { getOpenid4vpClientId } from '../client-identifier-prefix/parse-client-identifier-prefix'
import {
  validateOpenid4vpAuthorizationRequestPayload,
  type WalletVerificationOptions,
} from './validate-authorization-request'
import { validateOpenid4vpAuthorizationRequestDcApiPayload } from './validate-authorization-request-dc-api'
import { validateOpenid4vpAuthorizationRequestIaePayload } from './validate-authorization-request-iae'
import { type Openid4vpAuthorizationRequest, zOpenid4vpAuthorizationRequest } from './z-authorization-request'
import {
  isOpenid4vpAuthorizationRequestDcApi,
  type Openid4vpAuthorizationRequestDcApi,
  zOpenid4vpAuthorizationRequestDcApi,
} from './z-authorization-request-dc-api'
import {
  isOpenid4vpAuthorizationRequestIae,
  type Openid4vpAuthorizationRequestIae,
  zOpenid4vpAuthorizationRequestIae,
} from './z-authorization-request-iae'

export interface CreateOpenid4vpAuthorizationRequestOptions {
  scheme?: string
  authorizationRequestPayload:
    | Openid4vpAuthorizationRequest
    | Openid4vpAuthorizationRequestDcApi
    | Openid4vpAuthorizationRequestIae
  jar?: Pick<
    CreateJarAuthorizationRequestOptions,
    'additionalJwtPayload' | 'requestUri' | 'jwtSigner' | 'expiresInSeconds'
  >

  wallet?: WalletVerificationOptions
  callbacks: Pick<CallbackContext, 'signJws' | 'encryptJwe'>

  /**
   * Date that should be used as now, for the `iat` and `exp` of the request object. If not provided current
   * date will be used.
   */
  now?: Date
}

/**
 * Creates an OpenID4VP authorization request, optionally with a JWT Secured Authorization Request (JAR)
 * If the request is created after receiving wallet metadata via a POST to the request_uri endpoint, the wallet nonce needs to be provided
 *
 * @param options Configuration options for creating the authorization request
 * @param input.scheme Optional URI scheme to use (defaults to 'openid4vp://')
 * @param input.authorizationRequestPayload The OpenID4VP authorization request parameters
 * @param input.jar Optional JWT Secured Authorization Request (JAR) configuration
 * @param input.jar.requestUri The URI where the JAR will be accessible
 * @param input.jar.jwtSigner Function to sign the JAR JWT
 * @param input.jar.jweEncryptor Optional function to encrypt the JAR JWT
 * @param input.jar.additionalJwtPayload Optional additional claims to include in JAR JWT
 * @param input.wallet Optional wallet-specific parameters
 * @param input.wallet.nonce Optional wallet nonce
 * @param input.callbacks Callback functions for JWT operations
 * @returns Object containing the authorization request parameters, URI and optional JAR details
 */
export async function createOpenid4vpAuthorizationRequest(options: CreateOpenid4vpAuthorizationRequestOptions) {
  const { jar, scheme = 'openid4vp://', wallet, callbacks, now } = options

  let additionalJwtPayload: Record<string, unknown> | undefined

  let authorizationRequestPayload:
    | Openid4vpAuthorizationRequest
    | Openid4vpAuthorizationRequestDcApi
    | Openid4vpAuthorizationRequestIae
  if (isOpenid4vpAuthorizationRequestDcApi(options.authorizationRequestPayload)) {
    authorizationRequestPayload = parseWithErrorHandling(
      zOpenid4vpAuthorizationRequestDcApi,
      options.authorizationRequestPayload,
      'Invalid authorization request. Could not parse openid4vp dc_api authorization request.'
    )

    validateOpenid4vpAuthorizationRequestDcApiPayload({
      params: authorizationRequestPayload,
      isJarRequest: Boolean(jar),
      disableOriginValidation: true,
    })
  } else if (isOpenid4vpAuthorizationRequestIae(options.authorizationRequestPayload)) {
    authorizationRequestPayload = parseWithErrorHandling(
      zOpenid4vpAuthorizationRequestIae,
      options.authorizationRequestPayload,
      'Invalid authorization request. Could not parse openid4vp iae_post authorization request.'
    )

    validateOpenid4vpAuthorizationRequestIaePayload({
      params: authorizationRequestPayload,
      isJarRequest: Boolean(jar),
      disableExpectedUrlValidation: true,
    })
  } else {
    authorizationRequestPayload = parseWithErrorHandling(
      zOpenid4vpAuthorizationRequest,
      options.authorizationRequestPayload,
      'Invalid authorization request. Could not parse openid4vp authorization request.'
    )
    validateOpenid4vpAuthorizationRequestPayload({
      params: authorizationRequestPayload,
      walletVerificationOptions: wallet,
    })
  }

  const isJsonRequest =
    isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload) ||
    isOpenid4vpAuthorizationRequestIae(authorizationRequestPayload)

  if (!jar && !isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload)) {
    const { clientIdPrefix } = getOpenid4vpClientId({
      clientId: authorizationRequestPayload.client_id,
      legacyClientIdScheme: authorizationRequestPayload.client_id_scheme,
      responseMode: authorizationRequestPayload.response_mode,
    })

    if (clientIdPrefix !== 'pre-registered' && clientIdPrefix !== 'redirect_uri') {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Using client identifier prefix '${clientIdPrefix}' requires a signed JAR request.`,
      })
    }
  }

  if (jar) {
    additionalJwtPayload = !jar.additionalJwtPayload?.aud
      ? { ...jar.additionalJwtPayload, aud: 'https://self-issued.me/v2' }
      : jar.additionalJwtPayload

    const jarResult = await createJarAuthorizationRequest({
      ...jar,
      authorizationRequestPayload,
      additionalJwtPayload,
      callbacks,
      now,
    })

    const url = new URL(scheme)
    url.search = `?${new URLSearchParams([
      ...url.searchParams.entries(),
      ...objectToQueryParams(jarResult.jarAuthorizationRequest).entries(),
      // Add client_id_scheme if defined for backwards compat
      ...(authorizationRequestPayload.client_id_scheme
        ? [['client_id_scheme', authorizationRequestPayload.client_id_scheme]]
        : []),
    ]).toString()}`

    return {
      authorizationRequestPayload,
      authorizationRequestObject: jarResult.jarAuthorizationRequest,
      authorizationRequest: isJsonRequest ? jarResult.jarAuthorizationRequest : url.toString(),
      jar: { ...jar, ...jarResult },
    }
  }

  const url = new URL(scheme)
  url.search = `?${new URLSearchParams([
    ...url.searchParams.entries(),
    ...objectToQueryParams(authorizationRequestPayload).entries(),
  ]).toString()}`

  return {
    authorizationRequestPayload,
    authorizationRequestObject: authorizationRequestPayload,
    authorizationRequest: isJsonRequest ? authorizationRequestPayload : url.toString(),
    jar: undefined,
  }
}
