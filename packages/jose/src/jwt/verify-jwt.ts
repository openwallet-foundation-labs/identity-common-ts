import { type BaseSchema, parseWithErrorHandling } from '@owf/identity-common'
import type { VerifyJwsCallback } from '../callbacks'
import { JoseValidationError } from '../error'
import type { JwsSigner, JwsSignerMethod, JwsSignerWithJwk } from '../jws/signer'
import { verifyJwsSignature } from '../jws/verify-jws'
import type { InferSchemaOrDefaultOutput } from '../utils/zod'
import { type DecodeJwtResult, decodeJwt } from './decode-jwt'
import { type VerifyJwtClaimsOptions, verifyJwtClaims } from './verify-jwt-claims'
import { type JwtPayload, type zJwtHeader, zJwtPayload } from './z-jwt'

export interface VerifyJwtOptions<
  HeaderSchema extends BaseSchema | undefined,
  PayloadSchema extends BaseSchema | undefined,
> extends VerifyJwtClaimsOptions {
  /**
   * The JWT to verify: the compact serialization, or the result of a previous {@link decodeJwt} when
   * the caller had to look at the token before it could decide how to verify it.
   */
  jwt: string | DecodeJwtResult<HeaderSchema, PayloadSchema>

  /** Callback that verifies the signature and decides whether the key is trusted. */
  verifyJwsCallback: VerifyJwsCallback

  /**
   * Schema to validate the header with, see {@link decodeJwt}. Only used when `jwt` is a compact JWT.
   *
   * What it returns is the `header` that is returned, but the checks are made on the header as
   * validated against `zJwtHeader`, which the schema cannot change.
   */
  headerSchema?: HeaderSchema

  /**
   * Schema to validate the payload with, see {@link decodeJwt}. Only used when `jwt` is a compact JWT.
   *
   * What it returns is the `payload` that is returned, but the claims are verified as validated
   * against `zJwtPayload`, which the schema cannot change.
   */
  payloadSchema?: PayloadSchema

  /** The signer to verify against. Established from the header when not provided. */
  signer?: JwsSigner

  /** The signer methods the caller accepts. */
  allowedSignerMethods?: ReadonlyArray<JwsSignerMethod>

  /** Whether a header may identify the signer in more than one way, see `verifyJwsSignature`. */
  allowMultipleSignerMethods?: boolean

  /**
   * Whether a `kid` whose DID is not the `iss` is accepted for a did signer. Needed for
   * `openid4vci-proof+jwt`, where `iss` is the client id rather than the did.
   *
   * @default false
   */
  allowDidKidIssuerMismatch?: boolean

  /** The algorithms the caller accepts, see `verifyJwsSignature`. */
  allowedAlgorithms?: ReadonlyArray<string>

  /** Whether a symmetric signature algorithm is acceptable, see `verifyJwsSignature`. */
  allowSymmetricAlgorithms?: boolean

  /** The critical header parameters the caller understands. */
  understoodCriticalParameters?: ReadonlyArray<string>
}

export interface VerifyJwtResult<
  HeaderSchema extends BaseSchema | undefined = undefined,
  PayloadSchema extends BaseSchema | undefined = undefined,
> {
  header: InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>
  payload: InferSchemaOrDefaultOutput<PayloadSchema, typeof zJwtPayload>

  /** The signer, with the public key the signature was verified with. */
  signer: JwsSignerWithJwk

  /** The compact JWT that was verified. */
  compact: string
}

/**
 * Verifies a JWT completely: the signature over it, and then the claims in it.
 *
 * The signature is verified first, since the claims of a token whose signer has not been established
 * say nothing about anything.
 *
 * @throws JoseParseError or JoseValidationError if the token is not a valid JWT.
 * @throws JoseAlgorithmNotAllowedError if the algorithm is not accepted, or does not match the key.
 * @throws JoseSignatureVerificationError if the signature does not verify.
 * @throws JoseValidationError with an issue for each claim that does not verify, see `verifyJwtClaims`.
 * @throws JoseInvalidArgumentError if `now`, `skewSeconds` or `maxAgeSeconds` cannot be used to
 *   verify the claims.
 */
export async function verifyJwt<
  HeaderSchema extends BaseSchema | undefined = undefined,
  PayloadSchema extends BaseSchema | undefined = undefined,
>(options: VerifyJwtOptions<HeaderSchema, PayloadSchema>): Promise<VerifyJwtResult<HeaderSchema, PayloadSchema>> {
  const decoded =
    typeof options.jwt === 'string'
      ? decodeJwt({
          jwt: options.jwt,
          headerSchema: options.headerSchema,
          payloadSchema: options.payloadSchema,
          understoodCriticalParameters: options.understoodCriticalParameters,
        })
      : options.jwt

  const header = decoded.header as InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>
  const payload = decoded.payload as InferSchemaOrDefaultOutput<PayloadSchema, typeof zJwtPayload>

  // Every check is made on the header and claims as validated against the registered schemas, not on
  // what the caller's schemas made of them, which may have dropped `alg` or `exp`, or filled in `iat`.
  // A decoded JWT that was put together without `decodeJwt` does not come with them, so its own
  // header and claims are validated instead.
  const registeredPayload: JwtPayload =
    decoded.registeredPayload ??
    parseWithErrorHandling(zJwtPayload, decoded.payload, 'Invalid JWT payload', JoseValidationError)

  const { signer } = await verifyJwsSignature({
    jws: {
      protectedHeader: header,
      registeredProtectedHeader: decoded.registeredHeader,
      signingInput: decoded.signingInput,
      signature: decoded.signature,
      // The claims set as bytes, which is the payload of the JWS that the JWT is.
      payload: decoded.payloadBytes,
      compact: decoded.compact,
    },
    jwtPayload: registeredPayload,
    verifyJwsCallback: options.verifyJwsCallback,
    signer: options.signer,
    allowedSignerMethods: options.allowedSignerMethods,
    allowMultipleSignerMethods: options.allowMultipleSignerMethods,
    allowDidKidIssuerMismatch: options.allowDidKidIssuerMismatch,
    allowedAlgorithms: options.allowedAlgorithms,
    allowSymmetricAlgorithms: options.allowSymmetricAlgorithms,
    errorMessage: options.errorMessage ?? 'Error during verification of the JWT.',
  })

  verifyJwtClaims(registeredPayload, options)

  return { header, payload, signer, compact: decoded.compact }
}
