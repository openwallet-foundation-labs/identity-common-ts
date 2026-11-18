import type { OrPromise } from '@owf/identity-common'
import type { Jwk } from './jwk/z-jwk'
import type { JwsSigner } from './jws/signer'
import type { JwsProtectedHeader, JwsUnprotectedHeader } from './jws/z-jws'
import type { JwtPayload } from './jwt/z-jwt'

/**
 * What a signing or verification callback is given besides the signer. The callbacks sign and verify
 * the bytes this package computed, so a token is never validated in one form and signed in another.
 */
export interface JwsCallbackContext {
  /**
   * The exact bytes the signature is over: `BASE64URL(protected) || '.' || payload`. ASCII, unless the
   * payload is unencoded (RFC 7797) and detached or in a JSON serialization.
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

  /** The payload as a JSON object, when the JWS is a JWT, so a callback can use the claims. */
  jwtPayload?: JwtPayload
}

export interface SignJwsCallbackContext extends JwsCallbackContext {}

export interface VerifyJwsCallbackContext extends JwsCallbackContext {
  /** The signature to verify, base64url encoded. */
  signature: string

  /** The compact serialization, when the JWS was received that way and its payload is not detached. */
  compact?: string
}

/**
 * Signs `signingInputBytes` with the key of `signer`, and returns the base64url signature and the
 * public key it signed with.
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

  /** The public key the signature was created with. */
  signerJwk: Jwk
}>

/**
 * Verifies the signature, and decides whether the key is trusted (a certificate chain, a DID, ...):
 * the library only establishes which key signed. Returning `verified: false` and throwing both fail.
 */
export type VerifyJwsCallback = (
  signer: JwsSigner,
  context: VerifyJwsCallbackContext
) => OrPromise<{ verified: true; signerJwk: Jwk } | { verified: false; signerJwk?: Jwk }>
