import { base64url, stringToBytes } from '@owf/identity-common'
import type { SignJwsCallback } from '../callbacks'
import { JoseInvalidArgumentError, JoseParseError } from '../error'
import type { Jwk } from '../jwk/z-jwk'
import { decodeUnencodedPayload, encodeBase64UrlJson, unencodedCompactPayloadIssue } from '../utils/encoding'
import { zBase64Url } from '../utils/z-common'
import { parseWithErrorHandling } from '../utils/zod'
import { assertCriticalHeaderParameters, isPayloadBase64UrlEncoded } from './critical-headers'
import type { JwsSigner } from './signer'
import { zJwsProtectedHeader } from './z-jws'

export interface SignCompactJwsOptions {
  /**
   * The protected header. Validated against {@link zJwsProtectedHeader}, so a JWS with `alg: none`
   * or a malformed `crit` cannot be produced. Its `alg` must be the `alg` of the signer.
   */
  protectedHeader: Record<string, unknown>

  /**
   * The payload. An object is serialized as JSON; a string is encoded as UTF-8.
   */
  payload: Record<string, unknown> | string | Uint8Array

  /** The signer, which the callback resolves into a key. */
  signer: JwsSigner

  /** Callback that produces the signature. */
  signJwsCallback: SignJwsCallback

  /**
   * Whether to leave the payload out of the returned compact serialization, so that it is carried
   * out of band.
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

  /**
   * The bytes that were signed, as a string. ASCII, except for a detached unencoded payload
   * (`b64` false), which is in it as it is.
   */
  signingInput: string

  /** The public key the JWS was signed with, as reported by the callback. */
  signerJwk: Jwk
}

/**
 * Signs a JWS in compact serialization.
 *
 * The header and payload are serialized here and handed to the callback as the exact bytes to sign,
 * so that what is signed is what ends up in the token.
 *
 * @throws JoseValidationError if the protected header is not a valid JWS header.
 * @throws JoseCriticalHeaderError if `crit` is invalid.
 * @throws JoseNotSupportedError if the payload is unencoded (`b64` is false) and not valid UTF-8.
 * @throws JoseParseError if the payload is unencoded, is not detached, and contains a character that
 *   RFC 7797 does not allow in a compact serialization: a '.', or anything outside printable ASCII.
 * @throws JoseInvalidArgumentError if the signer uses another algorithm than the header names, or the
 *   callback does not return a base64url encoded signature.
 */
export async function signCompactJws(options: SignCompactJwsOptions): Promise<SignCompactJwsResult> {
  const protectedHeader = parseWithErrorHandling(
    zJwsProtectedHeader,
    options.protectedHeader,
    'Unable to sign the JWS, invalid header'
  )

  // A producer understands the parameters it marks critical itself, so only the structural rules
  // apply here — the 'is it understood' check is a rule for the recipient.
  assertCriticalHeaderParameters({ protectedHeader, understoodCriticalParameters: protectedHeader.crit ?? [] })

  // The callback signs with the algorithm of the signer, so a header naming another one would produce
  // a token that claims a signature it does not have.
  if (options.signer.alg !== protectedHeader.alg) {
    throw new JoseInvalidArgumentError(
      `Unable to sign the JWS, the header says alg '${protectedHeader.alg}' but the signer signs with alg '${options.signer.alg}'.`
    )
  }

  const payload =
    typeof options.payload === 'string'
      ? stringToBytes(options.payload)
      : options.payload instanceof Uint8Array
        ? options.payload
        : stringToBytes(JSON.stringify(options.payload))

  const isBase64UrlEncoded = isPayloadBase64UrlEncoded(protectedHeader)

  // The validated header is what gets serialized, so that what is signed is what was checked.
  const encodedProtectedHeader = encodeBase64UrlJson(protectedHeader)
  const encodedPayload = isBase64UrlEncoded ? base64url.encode(payload) : decodeUnencodedPayload(payload)
  const signingInput = `${encodedProtectedHeader}.${encodedPayload}`

  // RFC 7797 section 5.2: a compact serialization only carries an unencoded payload of printable ASCII
  // other than '.', which is what separates the parts.
  const compactPayloadIssue =
    !isBase64UrlEncoded && !options.detachPayload ? unencodedCompactPayloadIssue(encodedPayload) : undefined
  if (compactPayloadIssue) {
    throw new JoseParseError(
      `Unable to sign the JWS. ${compactPayloadIssue} Detach the payload, or leave out 'b64' so that it is base64url encoded.`
    )
  }

  const { signature, signerJwk } = await options.signJwsCallback(options.signer, {
    signingInput,
    signingInputBytes: stringToBytes(signingInput),
    protectedHeader,
    payload,
    jwtPayload:
      typeof options.payload === 'object' && !(options.payload instanceof Uint8Array) ? options.payload : undefined,
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
