import type { BaseSchema } from '@owf/identity-common'
import type z from 'zod'
import type { SignJwsCallback } from '../callbacks'
import { JoseNotSupportedError } from '../error'
import type { Jwk } from '../jwk/z-jwk'
import { signCompactJws } from '../jws/sign-jws'
import type { JwsSigner } from '../jws/signer'
import type { InferSchemaOrDefaultOutput, MarkOptional } from '../utils/zod'
import { parseWithErrorHandling } from '../utils/zod'
import { type JwtHeader, zJwtHeader, zJwtPayload } from './z-jwt'

export interface SignJwtOptions<
  HeaderSchema extends BaseSchema | undefined,
  PayloadSchema extends BaseSchema | undefined,
  Signer extends JwsSigner = JwsSigner,
> {
  /**
   * The header.
   *
   * Typed from `headerSchema` when one is given, with `alg` made optional: it is taken from the
   * signer, which is what says how the token is actually signed.
   *
   * The parameters that identify the key — `kid`, `jwk`, `x5c`, `trust_chain` — are not added: which
   * of them a token carries is decided by the token type, not by how the key happens to be
   * addressed. Spread {@link jwsHeaderFromSigner} into the header to add them.
   */
  header?: HeaderSchema extends BaseSchema ? MarkOptional<z.input<HeaderSchema>, 'alg'> : Record<string, unknown>

  /** The claims set. Typed from `payloadSchema` when one is given. */
  payload: PayloadSchema extends BaseSchema ? z.input<PayloadSchema> : Record<string, unknown>

  /**
   * Schema to validate the header with, on top of {@link zJwtHeader}, which is always applied.
   *
   * Pass the same schema the recipient verifies with, so that a token is checked against the profile
   * it is meant to satisfy before it is signed rather than after it is rejected.
   */
  headerSchema?: HeaderSchema

  /**
   * Schema to validate the claims set with, on top of {@link zJwtPayload}, which is always applied.
   */
  payloadSchema?: PayloadSchema

  /** The signer, which the callback resolves into a key. */
  signer: Signer

  /** Callback that produces the signature. */
  signJwsCallback: SignJwsCallback
}

export interface SignJwtResult<
  HeaderSchema extends BaseSchema | undefined = undefined,
  PayloadSchema extends BaseSchema | undefined = undefined,
> {
  /** The signed JWT in compact serialization. */
  jwt: string

  /** The public key the JWT was signed with, as reported by the callback. */
  signerJwk: Jwk

  /** The header that was signed. */
  header: InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>

  /** The claims set that was signed. */
  payload: InferSchemaOrDefaultOutput<PayloadSchema, typeof zJwtPayload>
}

/**
 * Signs a JWT.
 *
 * The header and the claims set are validated before they are signed, so that a token this library
 * produces is a token it would also accept. Passing the schemas of the token type being produced
 * extends that to the profile: a key binding JWT missing its `sd_hash` fails here rather than at the
 * verifier.
 *
 * What is signed is the validated value, so a schema that fills in a default or narrows a claim
 * shapes the token rather than being checked against it and then discarded. That value is validated
 * against the registered claims as well.
 *
 * @throws JoseValidationError if the header or the claims set is not valid.
 * @throws JoseNotSupportedError if the header sets `b64` to false, which is not valid for a JWT.
 */
export async function signJwt<
  HeaderSchema extends BaseSchema | undefined = undefined,
  PayloadSchema extends BaseSchema | undefined = undefined,
  Signer extends JwsSigner = JwsSigner,
>(options: SignJwtOptions<HeaderSchema, PayloadSchema, Signer>): Promise<SignJwtResult<HeaderSchema, PayloadSchema>> {
  // `alg` is applied last: the signer is what says how the token is signed, so the header must not
  // be able to claim a different algorithm than the one actually used.
  const headerJson = { ...options.header, alg: options.signer.alg }

  // Always validated against the registered header parameters and claims, and only then against the
  // caller's schemas, the same way `decodeJwt` validates a token that is read.
  parseWithErrorHandling(zJwtHeader, headerJson, 'Unable to sign the JWT, invalid header')
  const header = parseWithErrorHandling(
    options.headerSchema ?? zJwtHeader,
    headerJson,
    'Unable to sign the JWT, invalid header'
  )

  // RFC 7519 defines the claims set as base64url encoded JSON, so a JWT with an unencoded payload
  // (RFC 7797) would be a token that `decodeJwt` rejects. The header that is signed is the one the
  // caller's schema returned, which `signCompactJws` validates as a JWS header.
  if ((header as JwtHeader).b64 === false) {
    throw new JoseNotSupportedError(
      `Unable to sign the JWT, its header sets 'b64' to false. An unencoded payload is not valid for a JWT.`
    )
  }

  parseWithErrorHandling(zJwtPayload, options.payload, 'Unable to sign the JWT, invalid claims set')
  const payload = parseWithErrorHandling(
    options.payloadSchema ?? zJwtPayload,
    options.payload,
    'Unable to sign the JWT, invalid claims set'
  )

  // What the caller's schema returned is what gets signed, so it is validated against the registered
  // claims too: a schema that transforms or fills in a registered claim must not be able to sign one
  // that `decodeJwt` would reject.
  parseWithErrorHandling(zJwtPayload, payload, 'Unable to sign the JWT, invalid claims set')

  const { compact, signerJwk } = await signCompactJws({
    protectedHeader: header,
    payload,
    signer: options.signer,
    signJwsCallback: options.signJwsCallback,
  })

  return {
    jwt: compact,
    signerJwk,
    header: header as InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>,
    payload: payload as InferSchemaOrDefaultOutput<PayloadSchema, typeof zJwtPayload>,
  }
}
