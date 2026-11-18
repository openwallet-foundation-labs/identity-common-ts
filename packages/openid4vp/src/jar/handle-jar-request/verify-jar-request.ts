import {
  type CallbackContext,
  type JarRequestObjectPayload,
  Oauth2ErrorCodes,
  Oauth2ServerErrorResponseError,
  signedAuthorizationRequestJwtHeaderTyp,
  validateJarRequestParams,
  zJarRequestObjectPayload,
} from '@openid4vc/oauth2'
import { isJwtTyp, validationErrorMessage } from '@owf/identity-common'
import {
  type DecodeJwtResult,
  decodeJwt,
  decodeJwtHeader,
  JoseValidationError,
  JoseVerificationError,
  type Jwk,
  type JwsSigner,
  type JwsSignerWithJwk,
  jwsSignerFromHeader,
  verifyJwt,
  zCompactJwe,
  zCompactJwt,
} from '@owf/jose'
import { Openid4vpAuthorizationRequestError } from '../../authorization-request/Openid4vpAuthorizationRequestError'
import { isOpenid4vpResponseModeDcApi } from '../../authorization-request/z-authorization-request-dc-api'
import { isOpenid4vpResponseModeIae } from '../../authorization-request/z-authorization-request-iae'
import { zOpenid4vpAuthorizationRequestPayload } from '../../authorization-request/z-authorization-request-payload'
import { getOpenid4vpClientId } from '../../client-identifier-prefix/parse-client-identifier-prefix'
import {
  type VerifiedVerifierAttestation,
  verifyVerifierAttestation,
} from '../../client-identifier-prefix/verifier-attestation'
import {
  type ClientIdPrefix,
  type UniformClientIdPrefix,
  zClientIdPrefix,
} from '../../client-identifier-prefix/z-client-id-prefix'
import type { WalletMetadata } from '../../models/z-wallet-metadata'
import { parseAuthorizationRequestVersion } from '../../version'
import { fetchJarRequestObject } from '../jar-request-object/fetch-jar-request-object'
import type { Openid4vpJarAuthorizationRequest } from '../z-jar-authorization-request'

export interface VerifyJarRequestOptions {
  jarRequestParams: Openid4vpJarAuthorizationRequest

  /**
   * Whether to allow the JAR request to contain a remote
   * `request_uri` parameter that should be fetched.
   *
   * If set to false and the JAR request contains a
   * `request_uri` parameter the method will throw an error
   *
   * @default false
   */
  allowRequestUri?: boolean

  callbacks: Pick<CallbackContext, 'verifyJws' | 'decryptJwe' | 'fetch' | 'fetchLimits'>
  wallet?: {
    metadata?: WalletMetadata
    nonce?: string
  }

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

export interface VerifiedJarRequest {
  authorizationRequestPayload: JarRequestObjectPayload
  sendBy: 'value' | 'reference'
  decryptionJwk?: Jwk
  signer: JwsSignerWithJwk
  jwt: DecodeJwtResult<undefined, typeof zJarRequestObjectPayload>

  /** The verified Verifier Attestation JWT, when the client identifier prefix is `verifier_attestation` */
  verifierAttestation?: VerifiedVerifierAttestation
}

/**
 * Verifies a JAR (JWT Secured Authorization Request) request by validating, decrypting, and verifying signatures.
 *
 * @param options - The input parameters
 * @param options.jarRequestParams - The JAR authorization request parameters
 * @param options.callbacks - Context containing the relevant Jose crypto operations
 * @returns The verified authorization request parameters and metadata
 */
export async function verifyJarRequest(options: VerifyJarRequestOptions): Promise<VerifiedJarRequest> {
  const { callbacks, wallet = {} } = options

  const jarRequestParams = {
    ...options.jarRequestParams,
    ...validateJarRequestParams(options),
  } as Openid4vpJarAuthorizationRequest & ReturnType<typeof validateJarRequestParams>

  const sendBy = jarRequestParams.request ? 'value' : 'reference'

  // We can't know the client id prefix here if draft was before client_id_scheme became prefix
  const clientIdPrefix: ClientIdPrefix | undefined = jarRequestParams.client_id
    ? zClientIdPrefix.safeParse(jarRequestParams.client_id.split(':')[0]).data
    : 'origin'

  const method = jarRequestParams.request_uri_method ?? 'get'
  if (method !== 'get' && method !== 'post') {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestUriMethod,
      error_description: `Invalid request_uri_method. Must be 'get' or 'post'.`,
    })
  }

  const requestObject =
    jarRequestParams.request ??
    (await fetchJarRequestObject({
      requestUri: jarRequestParams.request_uri,
      clientIdPrefix,
      method,
      wallet,
      fetch: callbacks.fetch,
      fetchLimits: callbacks.fetchLimits,
    }))

  const requestObjectIsEncrypted = zCompactJwe.safeParse(requestObject).success
  const { decryptionJwk, payload: decryptedRequestObject } = requestObjectIsEncrypted
    ? await decryptJarRequest({ jwe: requestObject, callbacks })
    : { payload: requestObject, decryptionJwk: undefined }

  const requestIsSigned = zCompactJwt.safeParse(decryptedRequestObject).success
  if (!requestIsSigned) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'JAR request object is not a valid JWT.',
    })
  }

  try {
    const { authorizationRequestPayload, signer, jwt, verifierAttestation } = await verifyJarRequestObject({
      decryptedRequestObject,
      callbacks,
      now: options.now,
      allowedSkewInSeconds: options.allowedSkewInSeconds,
    })
    if (!authorizationRequestPayload.client_id) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequestObject,
        error_description: 'Jar Request Object is missing the required "client_id" field.',
      })
    }

    // Expect the client_id from the jar request to match the payload, but only if we're not using DC API / IAE
    if (
      !isOpenid4vpResponseModeDcApi(authorizationRequestPayload.response_mode) &&
      !isOpenid4vpResponseModeIae(authorizationRequestPayload.response_mode) &&
      jarRequestParams.client_id !== authorizationRequestPayload.client_id
    ) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'client_id does not match the request object client_id.',
      })
    }
    if (
      jarRequestParams.client_id_scheme &&
      jarRequestParams.client_id_scheme !== authorizationRequestPayload.client_id_scheme
    ) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'client_id_scheme does not match the request object client_id_scheme.',
      })
    }

    return {
      sendBy,
      jwt,
      authorizationRequestPayload,
      signer,
      decryptionJwk,
      verifierAttestation,
    }
  } catch (error) {
    throw withUnverifiedAuthorizationRequest(error, decryptedRequestObject)
  }
}

/**
 * The request object could be decoded, but not verified. The error can still be sent to the
 * `response_uri` in the request object, which is why the unverified payload is attached.
 */
function withUnverifiedAuthorizationRequest(error: unknown, requestObject: string) {
  const serverError =
    error instanceof Oauth2ServerErrorResponseError
      ? error
      : error instanceof JoseVerificationError
        ? new Oauth2ServerErrorResponseError(
            {
              error: Oauth2ErrorCodes.InvalidRequestObject,
              error_description: 'The signature of the request object could not be verified.',
            },
            { cause: error, internalMessage: error.message }
          )
        : // e.g. a request object that is expired or not yet valid
          error instanceof JoseValidationError
          ? new Oauth2ServerErrorResponseError(
              {
                error: Oauth2ErrorCodes.InvalidRequestObject,
                error_description: validationErrorMessage('The request object is not valid.', error.issues),
              },
              { cause: error, internalMessage: error.message }
            )
          : undefined
  if (!serverError) return error

  let payload: unknown
  try {
    payload = decodeJwt({ jwt: requestObject }).payload
  } catch {
    return error
  }

  const parsed = zOpenid4vpAuthorizationRequestPayload.safeParse(payload)
  if (!parsed.success) return error

  return new Openid4vpAuthorizationRequestError(serverError, { authorizationRequestPayload: parsed.data })
}

async function decryptJarRequest(options: { jwe: string; callbacks: Pick<CallbackContext, 'decryptJwe'> }) {
  const { jwe, callbacks } = options

  // NOTE: `decodeJwtHeader`, not `decodeJwt`: this is a compact JWE, which has five parts rather
  // than the three a JWS has, and only its header can be read before it is decrypted.
  const { header } = decodeJwtHeader({ jwt: jwe })
  if (!header.kid) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'Jar JWE is missing the protected header field "kid".',
    })
  }

  const decryptionResult = await callbacks.decryptJwe(jwe)
  if (!decryptionResult.decrypted) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'Failed to decrypt jar request object.',
    })
  }

  return decryptionResult
}

async function verifyJarRequestObject(options: {
  decryptedRequestObject: string
  callbacks: Pick<CallbackContext, 'verifyJws'>
  now?: Date
  allowedSkewInSeconds?: number
}) {
  const { decryptedRequestObject, callbacks } = options

  const jwt = decodeJwt({ jwt: decryptedRequestObject, payloadSchema: zJarRequestObjectPayload })

  let jwtSigner: JwsSigner
  let verifierAttestation: VerifiedVerifierAttestation | undefined

  const { clientIdPrefix, clientIdIdentifier } = getOpenid4vpClientId({
    responseMode: jwt.payload.response_mode,
    clientId: jwt.payload.client_id,
    legacyClientIdScheme: jwt.payload.client_id_scheme,
  })

  // Allowed signer methods for each of the client id schemes
  const clientIdToSignerMethod: Record<UniformClientIdPrefix, JwsSigner['method'][]> = {
    decentralized_identifier: ['did'],

    // The keys of a pre-registered client are registered with the wallet (OpenID4VP 1.0 Section 5.9), so they cannot
    // come from the request: with a `jwk` header or a DID such as did:jwk, anyone could sign for any client_id
    'pre-registered': ['custom', 'x5c'],
    origin: [], // no signing allowed
    redirect_uri: [], // no signing allowed

    // Handled separately
    verifier_attestation: [],

    x509_san_dns: ['x5c'],
    x509_san_uri: ['x5c'],
    x509_hash: ['x5c'],

    // Handled separately
    openid_federation: [],
  }

  // The logic to determine the signer for a JWT is different for signed authorization request and federation
  if (clientIdPrefix === 'openid_federation') {
    if (!jwt.header.kid) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequestObject,
        error_description: `When OpenID Federation is used for a signed authorization request, the 'kid' parameter is required.`,
      })
    }

    jwtSigner = {
      method: 'federation',
      alg: jwt.header.alg,
      trustChain: jwt.payload.trust_chain,
      kid: jwt.header.kid,
    }
  } else if (clientIdPrefix === 'verifier_attestation') {
    const redirectUri = jwt.payload.redirect_uri
    verifierAttestation = await verifyVerifierAttestation({
      verifierAttestationJwt: jwt.header.jwt,
      clientIdIdentifier,
      redirectUri: typeof redirectUri === 'string' ? redirectUri : undefined,
      callbacks,
      now: options.now,
      allowedSkewInSeconds: options.allowedSkewInSeconds,
    })

    // OpenID4VP 1.0 Section 5.9.3: the request is signed with the key in the `cnf` claim of the attestation
    jwtSigner = { method: 'jwk', alg: jwt.header.alg, publicJwk: verifierAttestation.payload.cnf.jwk }
  } else {
    jwtSigner = jwsSignerFromHeader({
      header: jwt.header,
      issuer: jwt.payload.iss,
      allowedSignerMethods: clientIdToSignerMethod[clientIdPrefix],
    })
  }

  const { signer } = await verifyJwt({
    verifyJwsCallback: callbacks.verifyJws,
    jwt,
    signer: jwtSigner,
    now: options.now,
    skewSeconds: options.allowedSkewInSeconds,
  })

  // biome-ignore lint/suspicious/noExplicitAny: no explanation
  const version = parseAuthorizationRequestVersion(jwt.payload as any)
  if (!isJwtTyp(jwt.header.typ, signedAuthorizationRequestJwtHeaderTyp) && version >= 24) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: `Invalid Jar Request Object typ header. Expected "oauth-authz-req+jwt", received "${jwt.header.typ}".`,
    })
  }

  return {
    signer,
    jwt,
    authorizationRequestPayload: jwt.payload,
    verifierAttestation,
  }
}
