import { createFetcher, type Fetch, zHttpsUrl } from '@openid4vc/utils'
import { CommonMediaTypes, createAcceptHeader, zTyp } from '@owf/identity-common'
import { decodeJwt, type JwsSigner, type JwsSignerWithJwk, verifyJwt, zCompactJwe, zCompactJwt } from '@owf/jose'
import type { CallbackContext } from '../../callbacks'
import { Oauth2ErrorCodes } from '../../common/z-oauth2-error'
import { Oauth2ServerErrorResponseError } from '../../error/Oauth2ServerErrorResponseError'
import { Oauth2MediaTypes } from '../../media-types'
import { type JarAuthorizationRequest, validateJarRequestParams } from '../z-jar-authorization-request'
import {
  type JarRequestObjectPayload,
  jwtAuthorizationRequestJwtHeaderTyp,
  signedAuthorizationRequestJwtHeaderTyp,
  zJarRequestObjectPayload,
} from '../z-jar-request-object'

export interface ParsedJarRequestOptions {
  jarRequestParams: JarAuthorizationRequest
  callbacks: Pick<CallbackContext, 'fetch'>

  /**
   * Whether the request object may be passed by reference using `request_uri`. If allowed,
   * the `request_uri` will be fetched, so only enable this if the request is expected to be
   * passed by reference.
   *
   * @default false
   */
  allowRequestUri?: boolean
}

export interface VerifyJarRequestOptions {
  jarRequestParams: {
    client_id?: string
  }
  authorizationRequestJwt: string
  callbacks: Pick<CallbackContext, 'verifyJws'>
  jwtSigner: JwsSigner

  /**
   * Date to verify the `exp`, `nbf` and `iat` of the request object against. If not provided the
   * current date will be used.
   */
  now?: Date

  /**
   * Allowed clock skew in seconds for the `exp`, `nbf` and `iat` checks.
   *
   * @default 30
   */
  allowedSkewInSeconds?: number
}

export interface ParsedJarRequest {
  authorizationRequestJwt: string
  sendBy: 'value' | 'reference'
}

export interface VerifiedJarRequest {
  authorizationRequestPayload: JarRequestObjectPayload
  signer: JwsSignerWithJwk
  jwt: ReturnType<typeof decodeJwt<undefined, typeof zJarRequestObjectPayload>>
}
/**
 * Parse a JAR (JWT Secured Authorization Request) request by validating and optionally fetch from uri.
 *
 * @param options - The input parameters
 * @param options.jarRequestParams - The JAR authorization request parameters
 * @param options.callbacks - Context containing the relevant Jose crypto operations
 * @returns An object containing the transmission method ('value' or 'reference') and the JWT request object.
 */
export async function parseJarRequest(options: ParsedJarRequestOptions): Promise<ParsedJarRequest> {
  const { callbacks } = options

  const jarRequestParams = {
    ...validateJarRequestParams(options),
    ...options.jarRequestParams,
  } as JarAuthorizationRequest & ReturnType<typeof validateJarRequestParams>

  const sendBy = jarRequestParams.request ? 'value' : 'reference'

  const authorizationRequestJwt =
    jarRequestParams.request ??
    (await fetchJarRequestObject({
      requestUri: jarRequestParams.request_uri,
      fetch: callbacks.fetch,
    }))

  return { sendBy, authorizationRequestJwt }
}

/**
 * Verifies a JAR (JWT Secured Authorization Request) request by validating and verifying signatures.
 *
 * @param options - The input parameters
 * @param options.jarRequestParams - The JAR authorization request parameters
 * @param options.callbacks - Context containing the relevant Jose crypto operations
 * @returns The verified authorization request parameters and metadata
 */
export async function verifyJarRequest(options: VerifyJarRequestOptions): Promise<VerifiedJarRequest> {
  const { jarRequestParams, authorizationRequestJwt, callbacks, jwtSigner, now, allowedSkewInSeconds } = options

  /* Encryption is not supported */
  const requestObjectIsEncrypted = zCompactJwe.safeParse(authorizationRequestJwt).success
  if (requestObjectIsEncrypted) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'Encrypted JWE request objects are not supported.',
    })
  }

  const requestIsSigned = zCompactJwt.safeParse(authorizationRequestJwt).success
  if (!requestIsSigned) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'JAR request object is not a valid JWT.',
    })
  }

  const { authorizationRequestPayload, signer, jwt } = await verifyJarRequestObject({
    authorizationRequestJwt,
    callbacks,
    jwtSigner,
    now,
    allowedSkewInSeconds,
  })
  if (!authorizationRequestPayload.client_id) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'Jar Request Object is missing the required "client_id" field.',
    })
  }

  // Expect the client_id from the jar request to match the payload
  if (jarRequestParams.client_id !== authorizationRequestPayload.client_id) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: 'client_id does not match the request object client_id.',
    })
  }

  return {
    jwt,
    authorizationRequestPayload,
    signer,
  }
}

async function fetchJarRequestObject(options: { requestUri: string; fetch?: Fetch }): Promise<string> {
  const { requestUri, fetch } = options

  if (!zHttpsUrl.safeParse(requestUri).success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestUri,
      error_description: `The 'request_uri' must be an https url.`,
    })
  }

  const response = await createFetcher(fetch)(requestUri, {
    method: 'get',
    headers: {
      Accept: createAcceptHeader([
        Oauth2MediaTypes.AuthorizationRequestJwt,
        CommonMediaTypes.Jwt,
        CommonMediaTypes.TextPlain,
      ]),
      'Content-Type': CommonMediaTypes.XWwwFormUrlencoded,
    },
  }).catch(() => {
    throw new Oauth2ServerErrorResponseError({
      error_description: `Fetching request_object from request_uri '${requestUri}' failed`,
      error: Oauth2ErrorCodes.InvalidRequestUri,
    })
  })

  if (!response.ok) {
    throw new Oauth2ServerErrorResponseError({
      error_description: `Fetching request_object from request_uri '${requestUri}' failed with status code '${response.status}'.`,
      error: Oauth2ErrorCodes.InvalidRequestUri,
    })
  }

  return await response.text()
}

const zJarRequestObjectTyp = zTyp(signedAuthorizationRequestJwtHeaderTyp, jwtAuthorizationRequestJwtHeaderTyp)

async function verifyJarRequestObject(options: {
  authorizationRequestJwt: string
  callbacks: Pick<CallbackContext, 'verifyJws'>
  jwtSigner: JwsSigner
  now?: Date
  allowedSkewInSeconds?: number
}) {
  const { authorizationRequestJwt, callbacks, jwtSigner, now, allowedSkewInSeconds } = options

  const jwt = decodeJwt({ jwt: authorizationRequestJwt, payloadSchema: zJarRequestObjectPayload })

  const { signer } = await verifyJwt({
    verifyJwsCallback: callbacks.verifyJws,
    jwt,
    signer: jwtSigner,
    now,
    skewSeconds: allowedSkewInSeconds,
  })

  // Some existing deployments may alternatively be using both type
  if (!zJarRequestObjectTyp.safeParse(jwt.header.typ).success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: `Invalid Jar Request Object typ header. Expected "oauth-authz-req+jwt" or "jwt", received "${jwt.header.typ}".`,
    })
  }

  return {
    signer,
    jwt,
    authorizationRequestPayload: jwt.payload,
  }
}
