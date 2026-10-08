import type { OrPromise } from '@owf/identity-common'
import type { Jwk } from './jwk/z-jwk'
import type { JwsSigner } from './jws/signer'
import type { JwsProtectedHeader, JwsUnprotectedHeader } from './jws/z-jws'

/**
 * What a signing or verification callback is given, besides the signer.
 *
 * The callbacks are low level: they sign and verify the bytes this package computed, rather than
 * producing or consuming a token of their own. That keeps the serialization — which is what the
 * signature is over — in one place, so a token can never be validated in one form and signed or
 * verified in another.
 */
export interface JwsCallbackContext {
  /**
   * The exact bytes the signature is computed over, as a string:
   * `BASE64URL(protected) || '.' || payload`.
   *
   * ASCII, except for an unencoded payload (RFC 7797, `b64` false) that is detached or in a JSON
   * serialization: that is in it as it is, and {@link signingInputBytes} holds its UTF-8 encoding.
   *
   * @see https://www.rfc-editor.org/rfc/rfc7515#section-5.1
   * @see https://www.rfc-editor.org/rfc/rfc7797#section-3
   */
  signingInput: string

  /** {@link signingInput} as bytes, which is what a signing API usually takes. */
  signingInputBytes: Uint8Array

  /** The protected header of the JWS. */
  protectedHeader: JwsProtectedHeader

  /** The unprotected header, for a JSON serialized JWS. Not covered by the signature. */
  unprotectedHeader?: JwsUnprotectedHeader

  /** The payload bytes. */
  payload: Uint8Array

  /**
   * The payload as a JSON object, when the JWS is a JWT.
   *
   * Provided so that a callback can take the claims into account — which trust anchors apply to an
   * issuer, for instance — without having to decode the payload a second time.
   */
  jwtPayload?: Record<string, unknown>
}

export interface SignJwsCallbackContext extends JwsCallbackContext {}

export interface VerifyJwsCallbackContext extends JwsCallbackContext {
  /** The signature to verify, base64url encoded. */
  signature: string

  /**
   * The compact serialization, when the JWS was received in that form and carries its payload.
   *
   * Not given for a detached payload: the compact serialization then has an empty payload part, so
   * verifying it as a whole would verify a different message than {@link signingInput}.
   */
  compact?: string
}

/**
 * Signs the signing input of a JWS.
 *
 * The callback resolves the key from `signer` — a DID URL, a certificate chain, a public JWK, or a
 * key id — signs `signingInputBytes` with it, and returns the signature base64url encoded together
 * with the public key it signed with.
 *
 * @example
 * ```ts
 * const signJws: SignJwsCallback = async (signer, { signingInputBytes }) => {
 *   const { keyId, publicJwk } = await resolveKey(signer)
 *   const signature = await kms.sign({ keyId, algorithm: signer.alg, data: signingInputBytes })
 *   return { signature: base64url.encode(signature), signerJwk: publicJwk }
 * }
 * ```
 */
export type SignJwsCallback = (
  signer: JwsSigner,
  context: SignJwsCallbackContext
) => OrPromise<{
  /** The signature, base64url encoded. */
  signature: string

  /**
   * The public key the signature was created with.
   *
   * Required, because a caller has no other way to learn which key actually signed — openid4vci
   * compares it against the `attested_keys` of a key attestation. A signer that holds only a handle
   * on the key, such as a key id in a remote KMS or a certificate, resolves the key rather than
   * leaving it out.
   */
  signerJwk: Jwk
}>

/**
 * Verifies the signature over the signing input of a JWS.
 *
 * Besides checking the signature, this is where the caller decides whether the key is one it trusts:
 * whether a certificate chain chains to a trusted root, whether a DID is acceptable, and so on. The
 * library establishes which key signed, never whether that key should be believed.
 *
 * Returning `verified: false` and throwing are both treated as a failed verification, so a callback
 * can do either.
 */
export type VerifyJwsCallback = (
  signer: JwsSigner,
  context: VerifyJwsCallbackContext
) => OrPromise<{ verified: true; signerJwk: Jwk } | { verified: false; signerJwk?: Jwk }>
