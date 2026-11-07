import { base64url, parseWithErrorHandling, stringToBytes, zBase64Url } from '@owf/identity-common'
import type { SignJwsCallback } from '../callbacks'
import { JoseInvalidArgumentError, JoseValidationError } from '../error'
import type { Jwk } from '../jwk/z-jwk'
import { decodeUnencodedPayload, encodeBase64UrlJson, unencodedCompactPayloadIssue } from '../utils/encoding'
import { assertCriticalHeaderParameters, isPayloadBase64UrlEncoded } from './critical-headers'
import type { JwsSigner } from './signer'
import { assertHeaderIdentifiesSigner } from './signer-header'
import { zJwsProtectedHeader } from './z-jws'

export interface SignCompactJwsOptions {
  /** The protected header, validated against {@link zJwsProtectedHeader}. Its `alg` must be the signer's. */
  protectedHeader: Record<string, unknown>

  /** The payload. An object is serialized as JSON, a string is encoded as UTF-8. */
  payload: Record<string, unknown> | string | Uint8Array

  /** The signer, which the callback resolves into a key. */
  signer: JwsSigner

  /** Callback that produces the signature. */
  signJwsCallback: SignJwsCallback

  /**
   * Whether to leave the payload out of the compact serialization, to carry it out of band.
   *
   * @default false
   */
  detachPayload?: boolean
}

export interface SignCompactJwsResult {
  /** The compact serialization. Its payload part is empty when `detachPayload` was set. */
  compact: string

  /** The signature, base64url encoded. */
  signature: string

  /** The bytes that were signed, as a string. */
  signingInput: string

  /** The public key the JWS was signed with, as reported by the callback. */
  signerJwk: Jwk
}

/**
 * Signs a JWS in compact serialization. The callback signs the exact bytes that end up in the token.
 *
 * @throws JoseValidationError if the protected header is not a valid JWS header.
 * @throws JoseValidationError with an `invalid_crit` issue if `crit` is invalid.
 * @throws JoseNotSupportedError if the payload is unencoded (`b64` is false) and not valid UTF-8.
 * @throws JoseInvalidArgumentError if the signer uses another algorithm than the header names, the
 *   header identifies another signer (a `kid`, `x5c`, `jwk` or `trust_chain` that is not the signer's, or
 *   one of another signer method), the
 *   callback does not return a base64url encoded signature, or the payload is unencoded, not detached,
 *   and contains a character RFC 7797 does not allow in a compact serialization: a '.', or anything
 *   outside printable ASCII.
 */
export async function signCompactJws(options: SignCompactJwsOptions): Promise<SignCompactJwsResult> {
  const protectedHeader = parseWithErrorHandling(
    zJwsProtectedHeader,
    options.protectedHeader,
    'Unable to sign the JWS, invalid header',
    JoseValidationError
  )

  // A producer understands what it marks critical
  assertCriticalHeaderParameters({ protectedHeader, understoodCriticalParameters: protectedHeader.crit ?? [] })

  if (options.signer.alg !== protectedHeader.alg) {
    throw new JoseInvalidArgumentError(
      `Unable to sign the JWS, the header says alg '${protectedHeader.alg}' but the signer signs with alg '${options.signer.alg}'.`
    )
  }

  const jwtPayload =
    typeof options.payload === 'object' && !(options.payload instanceof Uint8Array) ? options.payload : undefined
  assertHeaderIdentifiesSigner(
    protectedHeader,
    options.signer,
    typeof jwtPayload?.iss === 'string' ? jwtPayload.iss : undefined
  )

  const payload =
    typeof options.payload === 'string'
      ? stringToBytes(options.payload)
      : options.payload instanceof Uint8Array
        ? options.payload
        : stringToBytes(JSON.stringify(options.payload))

  const isBase64UrlEncoded = isPayloadBase64UrlEncoded(protectedHeader)

  const encodedProtectedHeader = encodeBase64UrlJson(protectedHeader)
  const encodedPayload = isBase64UrlEncoded ? base64url.encode(payload) : decodeUnencodedPayload(payload)
  const signingInput = `${encodedProtectedHeader}.${encodedPayload}`

  // RFC 7797 section 5.2
  const compactPayloadIssue =
    !isBase64UrlEncoded && !options.detachPayload ? unencodedCompactPayloadIssue(encodedPayload) : undefined
  if (compactPayloadIssue) {
    throw new JoseInvalidArgumentError(
      `Unable to sign the JWS. ${compactPayloadIssue} Detach the payload, or leave out 'b64' so that it is base64url encoded.`
    )
  }

  const { signature, signerJwk } = await options.signJwsCallback(options.signer, {
    signingInput,
    signingInputBytes: stringToBytes(signingInput),
    protectedHeader,
    payload,
    jwtPayload,
  })

  // The signature is written into the token as it is, so it has to be what a parser accepts there
  if (!zBase64Url.min(1).safeParse(signature).success) {
    throw new JoseInvalidArgumentError(
      'Unable to sign the JWS, the signature returned by the signing callback is not a non-empty base64url string.'
    )
  }

  return {
    compact: `${encodedProtectedHeader}.${options.detachPayload ? '' : encodedPayload}.${signature}`,
    signature,
    signingInput,
    signerJwk,
  }
}
