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
 * The parts of a parsed JWS that verification needs. Without `registeredProtectedHeader`,
 * `protectedHeader` is validated against {@link zJwsProtectedHeader} and used instead.
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
   * The signer to verify against. Its `alg` must be the `alg` of the JWS. Established from the header
   * when not provided, see {@link jwsSignerFromHeader}.
   */
  signer?: JwsSigner

  /** The signer methods the caller accepts, used when the signer is established from the header. */
  allowedSignerMethods?: ReadonlyArray<JwsSignerMethod>

  /**
   * See {@link JwsSignerFromHeaderOptions.allowMultipleSignerMethods}.
   *
   * @default false
   */
  allowMultipleSignerMethods?: boolean

  /**
   * See {@link JwsSignerFromHeaderOptions.allowDidKidIssuerMismatch}.
   *
   * @default false
   */
  allowDidKidIssuerMismatch?: boolean

  /**
   * The algorithms the caller accepts: pass the ones the signer is known to use. Without it, any
   * algorithm is accepted except `none`, symmetric ones and registered ones in a different casing.
   */
  allowedAlgorithms?: ReadonlyArray<string>

  /**
   * Whether `HS256`, `HS384` and `HS512` are accepted. Off by default, as with a symmetric algorithm
   * every verifier can also issue a token.
   *
   * @default false
   */
  allowSymmetricAlgorithms?: boolean

  /** The payload as a JSON object, when the JWS is a JWT. Passed to the callback, and a did signer is bound to its `iss`. */
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
 * The algorithm policy of {@link verifyJwsSignature}, for code that verifies a signature without a
 * {@link VerifyJwsCallback}.
 *
 * @throws JoseAlgorithmNotAllowedError if the algorithm is not accepted.
 */
export function assertJwsAlgorithmAllowed({
  alg,
  allowedAlgorithms,
  allowSymmetricAlgorithms = false,
  errorMessage = 'Error during verification of the JWS.',
}: AssertJwsAlgorithmAllowedOptions): void {
  // `alg` does not have to come from a parsed header
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
 * Verifies the signature over a parsed JWS: the algorithm policy before the callback, and the key the
 * callback returns against the algorithm after it.
 *
 * @throws JoseAlgorithmNotAllowedError if the algorithm is not accepted, or does not match the key or
 *   the `alg` of the given `signer`.
 * @throws JoseSignatureVerificationError if the signature does not verify.
 * @throws JoseSignerError if the signer cannot be established from the header.
 * @throws JoseValidationError if the JWS has no `registeredProtectedHeader`, and its `protectedHeader`
 *   is not a valid JWS protected header.
 */
export async function verifyJwsSignature(options: VerifyJwsSignatureOptions): Promise<VerifyJwsSignatureResult> {
  const errorMessage = options.errorMessage ?? 'Error during verification of the JWS.'

  // Security checks use the registered header, not what a caller's schema made of it
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

  // The callback verifies with `signer.alg`, so it must be the alg the policy was applied to
  if (options.signer && options.signer.alg !== alg) {
    throw new JoseAlgorithmNotAllowedError(
      `${errorMessage} The JWS uses alg '${alg}', but the signer to verify against uses alg '${options.signer.alg}'.`
    )
  }

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

    // Without the key, it cannot be checked against the algorithm below
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
