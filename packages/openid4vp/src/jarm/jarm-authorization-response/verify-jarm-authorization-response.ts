import { type CallbackContext, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { parseWithErrorHandling, stringToJsonWithErrorHandling } from '@openid4vc/utils'
import {
  decodeJwt,
  decodeJwtHeader,
  JoseAlgorithmNotAllowedError,
  JoseSignerError,
  type Jwk,
  verifyJwt,
  zCompactJwe,
  zCompactJwt,
  zJwtHeader,
} from '@owf/jose'
import type { Openid4vpAuthorizationRequest } from '../../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../../authorization-request/z-authorization-request-dc-api'
import { extractEncryptionJwkFromJwks } from '../jarm-extract-jwks'
import { jarmAuthorizationResponseValidate } from './jarm-validate-authorization-response'
import {
  type JarmAuthorizationResponse,
  type JarmAuthorizationResponseEncryptedOnly,
  zJarmAuthorizationResponse,
  zJarmAuthorizationResponseEncryptedOnly,
} from './z-jarm-authorization-response'

export enum JarmMode {
  Signed = 'Signed',
  Encrypted = 'Encrypted',
  SignedEncrypted = 'SignedEncrypted',
}

/**
 * The header of a signed response has to identify the key that signed it: by the `jwk` or `x5c` it
 * carries, or otherwise by its `kid`, which is resolved together with the `iss` of the response.
 */
const zSignedJarmAuthorizationResponseHeader = zJwtHeader.refine(
  ({ kid, jwk, x5c }) => kid !== undefined || jwk !== undefined || x5c !== undefined,
  { message: `The header must identify the signing key with a 'kid', 'jwk' or 'x5c' parameter` }
)

/** Why the signature of a signed response was not accepted, as reported in the error response. */
function signatureVerificationErrorDescription(error: unknown) {
  if (error instanceof JoseAlgorithmNotAllowedError) {
    return 'The JARM authorization response is signed with an algorithm that is not allowed.'
  }

  if (error instanceof JoseSignerError) {
    return 'The signer of the JARM authorization response could not be established.'
  }

  return 'The signature of the JARM authorization response is not valid.'
}

/**
 * The client decrypts the JWT using the default key for the respective issuer or,
 * if applicable, determined by the kid JWT header parameter.
 * The key might be a private key, where the corresponding public key is registered
 * with the expected issuer of the response ("use":"enc" via the client's metadata jwks or jwks_uri)
 * or a key derived from its client secret (see Section 2.2).
 */
const decryptJarmAuthorizationResponseJwt = async (options: {
  jarmAuthorizationResponseJwt: string
  callbacks: Pick<CallbackContext, 'decryptJwe'>
  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
}) => {
  const { jarmAuthorizationResponseJwt, callbacks, authorizationRequestPayload } = options

  let encryptionJwk: Jwk | undefined
  const { header } = decodeJwtHeader({
    jwt: jarmAuthorizationResponseJwt,
  })

  // NOTE: previously we required `kid` to be present in the JARM header, but not all implementations seem to
  // add this, so we removed the check. Starting from draft 26 it's required again, so we can add the check again when
  // removing support for drafts <26
  if (authorizationRequestPayload.client_metadata?.jwks) {
    //  If there's no kid, we try to extract the JWK from the request, if we are not successful
    // (because e.g. the request used client_metadata_uri) the decryptJwe callback has to handle this edge case
    // See https://github.com/openid/OpenID4VP/issues/441
    encryptionJwk = extractEncryptionJwkFromJwks(authorizationRequestPayload.client_metadata.jwks, {
      // Kid always take precedence
      kid: header.kid,

      // This value was removed in draft 26, but if it's still provided, we can use it to determine the key to use
      supportedAlgValues: authorizationRequestPayload.client_metadata.authorization_encrypted_response_alg
        ? [authorizationRequestPayload.client_metadata.authorization_encrypted_response_alg]
        : undefined,
    })
  }

  const result = await callbacks.decryptJwe(jarmAuthorizationResponseJwt, { jwk: encryptionJwk })
  if (!result.decrypted) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: 'Failed to decrypt the JARM authorization response.',
    })
  }

  return {
    decryptionJwk: result.decryptionJwk,
    payload: result.payload,
  }
}

export interface VerifyJarmAuthorizationResponseOptions {
  jarmAuthorizationResponseJwt: string

  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi

  /**
   * The client id of the authorization request. This should be the effective client id,
   * meaning that if no client_id was present in the authorization request and DC API is used
   * it should be `web-origin:<origin>` (until draft 24) or `origin:<origin>` (from draft 25)
   */
  expectedClientId: string

  callbacks: Pick<CallbackContext, 'decryptJwe' | 'verifyJws'>
}

export type VerifiedJarmAuthorizationResponse = Awaited<ReturnType<typeof verifyJarmAuthorizationResponse>>

/**
 * Validate a JARM direct_post.jwt compliant authentication response
 * * The decryption key should be resolvable using the the protected header's 'kid' field
 * * The signature verification jwk should be resolvable using the jws protected header's 'jwk' or 'x5c' field, or
 *   otherwise its 'kid' field and the payload's 'iss' field.
 *
 * @throws Oauth2ServerErrorResponseError with error `invalid_request` when the response cannot be decrypted, its
 *   signature does not verify, or its `aud`, `exp`, `nbf` or `iat` is not valid. When `@owf/jose` rejected the
 *   signature or a time claim, its error is the `cause`.
 * @throws JoseValidationError when the header or the claims of a signed response do not validate, and the
 *   `ValidationError` of `@owf/identity-common` when the parameters of a response that is only encrypted do not.
 */
export async function verifyJarmAuthorizationResponse(options: VerifyJarmAuthorizationResponseOptions) {
  const { jarmAuthorizationResponseJwt, callbacks, expectedClientId, authorizationRequestPayload } = options

  const requestDataIsEncrypted = zCompactJwe.safeParse(jarmAuthorizationResponseJwt).success
  const decryptedRequestData = requestDataIsEncrypted
    ? await decryptJarmAuthorizationResponseJwt({
        jarmAuthorizationResponseJwt,
        callbacks,
        authorizationRequestPayload,
      })
    : { payload: jarmAuthorizationResponseJwt, decryptionJwk: undefined }

  const responseIsSigned = zCompactJwt.safeParse(decryptedRequestData.payload).success
  if (!requestDataIsEncrypted && !responseIsSigned) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: 'The JARM authorization response must be either encrypted, signed, or signed and encrypted.',
    })
  }

  let jarmAuthorizationResponse: JarmAuthorizationResponse | JarmAuthorizationResponseEncryptedOnly

  if (responseIsSigned) {
    const decodedJwt = decodeJwt({
      jwt: decryptedRequestData.payload,
      headerSchema: zSignedJarmAuthorizationResponseHeader,
      payloadSchema: zJarmAuthorizationResponse,
    })

    try {
      await verifyJwt({
        jwt: decodedJwt,
        verifyJwsCallback: options.callbacks.verifyJws,
        // The time claims are verified below together with the other claims, the same way for a
        // response that is signed as for one that is only encrypted
        checkExpirationTime: false,
        checkNotBefore: false,
        checkIssuedAt: false,
      })
    } catch (error) {
      // The jose error, which says what did not verify, is kept as the cause
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description: signatureVerificationErrorDescription(error),
        },
        { cause: error }
      )
    }

    jarmAuthorizationResponse = decodedJwt.payload
  } else {
    const jsonRequestData = stringToJsonWithErrorHandling(
      decryptedRequestData.payload,
      'Unable to parse decrypted JARM JWE body to JSON'
    )
    jarmAuthorizationResponse = parseWithErrorHandling(
      zJarmAuthorizationResponseEncryptedOnly,
      jsonRequestData,
      'Invalid JARM authorization response'
    )
  }

  jarmAuthorizationResponseValidate({
    expectedClientId,
    authorizationResponse: jarmAuthorizationResponse,
  })
  const type: JarmMode =
    requestDataIsEncrypted && responseIsSigned
      ? JarmMode.SignedEncrypted
      : requestDataIsEncrypted
        ? JarmMode.Encrypted
        : JarmMode.Signed

  const issuer = jarmAuthorizationResponse.iss
  return {
    jarmAuthorizationResponse,
    type,
    issuer,
    decryptionJwk: decryptedRequestData.decryptionJwk,
  }
}
