import { parseWithErrorHandling, stringToBytes } from '@owf/identity-common'
import type { VerifyJwsCallback } from '../callbacks'
import { JoseAlgorithmNotAllowedError, JoseSignatureVerificationError, JoseValidationError } from '../error'
import { isJwaSignatureAlgorithmCaseVariant, isSymmetricSignatureAlgorithm } from '../jwa/algorithms'
import { assertKeyAllowedForSignatureAlgorithm } from '../jwa/key-compatibility'
import { zJwsAlg } from '../jwa/z-alg'
import { zJwk } from '../jwk/z-jwk'
import type { ParsedJws } from './parse-jws'
import type { JwsSigner, JwsSignerMethod, JwsSignerWithJwk } from './signer'
import { jwsSignerFromHeader } from './signer'
import { zJwsProtectedHeader } from './z-jws'

/**
 * The parts of a parsed JWS that verifying a signature needs.
 *
 * The checks are made on `registeredProtectedHeader`, which `parseJws` returns. A JWS that was put
 * together otherwise can leave it out, and then `protectedHeader` is validated against
 * {@link zJwsProtectedHeader} and used in its place.
 */
export type VerifiableJws = Pick<
  ParsedJws,
  'protectedHeader' | 'unprotectedHeader' | 'signingInput' | 'signature' | 'payload' | 'compact'
> &
  Partial<Pick<ParsedJws, 'registeredProtectedHeader'>>

export interface VerifyJwsSignatureOptions {
  /** The parsed JWS, as returned by `parseJws`. */
  jws: VerifiableJws

  /** Callback that verifies the signature and decides whether the key is trusted. */
  verifyJwsCallback: VerifyJwsCallback

  /**
   * The signer to verify against. Established from the header when not provided, see
   * {@link jwsSignerFromHeader}.
   */
  signer?: JwsSigner

  /** The signer methods the caller accepts, used when the signer is established from the header. */
  allowedSignerMethods?: ReadonlyArray<JwsSignerMethod>

  /**
   * Whether to accept a header that identifies the signer in more than one way, when the signer is
   * established from the header. See {@link jwsSignerFromHeader}.
   *
   * @default false
   */
  allowMultipleSignerMethods?: boolean

  /**
   * Whether a `kid` whose DID is not the `iss` is accepted for a did signer, when the signer is
   * established from the header. Needed for `openid4vci-proof+jwt`, where `iss` is the client id
   * rather than the did. See {@link jwsSignerFromHeader}.
   *
   * @default false
   */
  allowDidKidIssuerMismatch?: boolean

  /**
   * The algorithms the caller accepts.
   *
   * Which algorithms are acceptable is a decision about the key and the issuer, not something the
   * token gets to choose, so pass the algorithms the signer is known to use wherever they are known.
   * When not provided, any algorithm is accepted — including one this package does not know — except
   * `none`, a symmetric algorithm (see {@link allowSymmetricAlgorithms}) and a registered algorithm in
   * a different casing, and it is up to the verification callback to reject the ones it cannot handle.
   */
  allowedAlgorithms?: ReadonlyArray<string>

  /**
   * Whether a symmetric signature algorithm (`HS256`, `HS384`, `HS512`) is acceptable.
   *
   * Off by default: with a symmetric algorithm every party that can verify a token can also issue
   * one, so accepting one where an asymmetric signature was expected turns a public key into a
   * shared secret.
   *
   * @default false
   */
  allowSymmetricAlgorithms?: boolean

  /**
   * The payload as a JSON object, when the JWS is a JWT. Passed through to the callback, and its `iss`
   * is what a did signer is bound to. Pass the claims as validated against `zJwtPayload`, not as a
   * schema of the caller's returned them, as `verifyJwt` does.
   */
  jwtPayload?: Record<string, unknown>

  /** Prefix for the error thrown when verification fails. */
  errorMessage?: string
}

export interface AssertJwsAlgorithmAllowedOptions {
  /** The `alg` of the JWS. */
  alg: string

  /** The algorithms the caller accepts. See {@link VerifyJwsSignatureOptions.allowedAlgorithms}. */
  allowedAlgorithms?: ReadonlyArray<string>

  /** Whether a symmetric signature algorithm is acceptable. See {@link VerifyJwsSignatureOptions.allowSymmetricAlgorithms}. */
  allowSymmetricAlgorithms?: boolean

  /** Prefix for the error thrown when the algorithm is not accepted. */
  errorMessage?: string
}

/**
 * Applies the algorithm policy {@link verifyJwsSignature} applies before a signature is verified:
 * the algorithm must not be `none`, must not be a registered algorithm in a different casing, must be
 * one the caller allows, and must not be symmetric unless that is allowed.
 *
 * Exported for the places that verify a signature without a {@link VerifyJwsCallback} — a callback
 * that only returns whether the signature is valid, and not the key — so that the same policy holds
 * there.
 *
 * @throws JoseAlgorithmNotAllowedError if the algorithm is not accepted.
 */
export function assertJwsAlgorithmAllowed({
  alg,
  allowedAlgorithms,
  allowSymmetricAlgorithms = false,
  errorMessage = 'Error during verification of the JWS.',
}: AssertJwsAlgorithmAllowedOptions): void {
  // A header that was parsed is already validated against `zJwsAlg`, but the `alg` given here does not
  // have to come from one, and an unsecured JWS must not get through either way.
  if (!zJwsAlg.safeParse(alg).success) {
    throw new JoseAlgorithmNotAllowedError(
      `${errorMessage} The JWS uses alg '${alg}', which is not a signature algorithm. An unsecured JWS is never accepted.`
    )
  }

  if (isJwaSignatureAlgorithmCaseVariant(alg)) {
    throw new JoseAlgorithmNotAllowedError(
      `${errorMessage} The JWS uses alg '${alg}', which differs from a registered algorithm only in casing. Algorithm names are case-sensitive.`
    )
  }

  if (allowedAlgorithms && !allowedAlgorithms.includes(alg)) {
    throw new JoseAlgorithmNotAllowedError(
      `${errorMessage} The JWS uses alg '${alg}', but the allowed algorithms are ${allowedAlgorithms
        .map((allowed) => `'${allowed}'`)
        .join(', ')}.`
    )
  }

  if (isSymmetricSignatureAlgorithm(alg) && !allowSymmetricAlgorithms) {
    throw new JoseAlgorithmNotAllowedError(
      `${errorMessage} The JWS uses the symmetric algorithm '${alg}'. Set 'allowSymmetricAlgorithms' if a MAC is expected here.`
    )
  }
}

export interface VerifyJwsSignatureResult {
  /** The signer, with the public key the signature was verified with. */
  signer: JwsSignerWithJwk
}

/**
 * Verifies the signature over a parsed JWS.
 *
 * The algorithm policy is applied before the callback is called, and the key the callback reports
 * having verified with is checked against the algorithm afterwards — a token cannot be verified
 * against a key that is not usable with the algorithm it claims to use.
 *
 * This verifies the signature only. For a JWT, `verifyJwt` also verifies the claims, which is what a
 * verifier wants: the claims of a token whose signer has not been established mean nothing.
 *
 * @throws JoseAlgorithmNotAllowedError if the algorithm is not accepted, or does not match the key.
 * @throws JoseSignatureVerificationError if the signature does not verify.
 * @throws JoseSignerError if the signer cannot be established from the header.
 * @throws JoseValidationError if the JWS has no `registeredProtectedHeader`, and its `protectedHeader`
 *   is not a valid JWS protected header.
 */
export async function verifyJwsSignature(options: VerifyJwsSignatureOptions): Promise<VerifyJwsSignatureResult> {
  const errorMessage = options.errorMessage ?? 'Error during verification of the JWS.'

  // The algorithm policy, the signer and the key check are security decisions, so they are made on
  // the header as validated against the registered parameters, not on what a caller's schema made of
  // it. A JWS that was not parsed by `parseJws` does not come with that header: its own is validated.
  const protectedHeader =
    options.jws.registeredProtectedHeader ??
    parseWithErrorHandling(
      zJwsProtectedHeader,
      options.jws.protectedHeader,
      'Invalid JWS protected header',
      JoseValidationError
    )
  const alg = protectedHeader.alg

  assertJwsAlgorithmAllowed({
    alg,
    allowedAlgorithms: options.allowedAlgorithms,
    allowSymmetricAlgorithms: options.allowSymmetricAlgorithms,
    errorMessage,
  })

  const signer =
    options.signer ??
    jwsSignerFromHeader({
      header: protectedHeader,
      issuer: typeof options.jwtPayload?.iss === 'string' ? options.jwtPayload.iss : undefined,
      allowedSignerMethods: options.allowedSignerMethods,
      allowMultipleSignerMethods: options.allowMultipleSignerMethods,
      allowDidKidIssuerMismatch: options.allowDidKidIssuerMismatch,
    })

  let signerJwk: JwsSignerWithJwk['publicJwk']
  try {
    const result = await options.verifyJwsCallback(signer, {
      signingInput: options.jws.signingInput,
      signingInputBytes: stringToBytes(options.jws.signingInput),
      protectedHeader,
      unprotectedHeader: options.jws.unprotectedHeader,
      payload: options.jws.payload,
      jwtPayload: options.jwtPayload,
      signature: options.jws.signature,
      compact: options.jws.compact,
    })

    if (!result.verified) throw new JoseSignatureVerificationError(errorMessage)

    // Without the key, it cannot be checked against the algorithm below, so the signature cannot be
    // accepted either
    if (!zJwk.safeParse(result.signerJwk).success) {
      throw new JoseSignatureVerificationError(
        `${errorMessage} The verification callback reported the signature as verified, but did not return the jwk it was verified with.`
      )
    }
    signerJwk = result.signerJwk
  } catch (error) {
    if (error instanceof JoseSignatureVerificationError) throw error
    throw new JoseSignatureVerificationError(errorMessage, { cause: error })
  }

  assertKeyAllowedForSignatureAlgorithm({
    jwk: signerJwk,
    alg,
    errorMessage: `${errorMessage} The key the JWS was verified with cannot be used with its algorithm.`,
  })

  return { signer: { ...signer, publicJwk: signerJwk } }
}
