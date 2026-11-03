import { type BaseSchema, parseWithErrorHandling } from '@owf/identity-common'
import { JoseNotSupportedError, JoseParseError, JoseValidationError } from '../error'
import { zJweHeader } from '../jwe/z-jwe'
import { parseJws } from '../jws/parse-jws'
import { decodeBase64UrlJsonObject } from '../utils/encoding'
import type { InferSchemaOrDefaultOutput } from '../utils/zod'
import { type JwtHeader, type JwtPayload, zJwtHeader, zJwtPayload } from './z-jwt'

export interface DecodeJwtOptions<
  HeaderSchema extends BaseSchema | undefined,
  PayloadSchema extends BaseSchema | undefined,
> {
  /** The compact encoded JWT. */
  jwt: string

  /**
   * Schema to validate the header with, on top of {@link zJwtHeader}, which is always applied.
   */
  headerSchema?: HeaderSchema

  /**
   * Schema to validate the payload with, on top of {@link zJwtPayload}, which is always applied so
   * that a registered claim always has the shape RFC 7519 gives it.
   */
  payloadSchema?: PayloadSchema

  /** The critical header parameters the caller understands. */
  understoodCriticalParameters?: ReadonlyArray<string>
}

export interface DecodeJwtResult<
  HeaderSchema extends BaseSchema | undefined = undefined,
  PayloadSchema extends BaseSchema | undefined = undefined,
> {
  /** The header, as `headerSchema` returned it. */
  header: InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>

  /** The claims set, as `payloadSchema` returned it. */
  payload: InferSchemaOrDefaultOutput<PayloadSchema, typeof zJwtPayload>

  /**
   * The header as validated against {@link zJwtHeader} alone, whatever `headerSchema` was given.
   *
   * `verifyJwt` makes its checks on this rather than on {@link header}: a schema of the caller's can
   * drop or change the parameters the checks depend on.
   */
  registeredHeader: JwtHeader

  /**
   * The claims set as validated against {@link zJwtPayload} alone, whatever `payloadSchema` was given.
   *
   * `verifyJwt` verifies the claims on this rather than on {@link payload}, so that a schema that
   * drops `exp` or fills in `iat` cannot change the outcome.
   */
  registeredPayload: JwtPayload

  /** The claims set as bytes, exactly as they were carried in the token. */
  payloadBytes: Uint8Array

  /** The signature, base64url encoded. */
  signature: string

  /** The bytes covered by the signature, as an ASCII string. */
  signingInput: string

  /** The compact JWT that was decoded. */
  compact: string
}

/**
 * Decodes a JWT and validates its header and payload, without verifying the signature.
 *
 * Everything is decoded through `@owf/identity-common`, so a token with an invalid base64url
 * alphabet, invalid UTF-8 or invalid JSON is rejected rather than being decoded into something that
 * looks close enough.
 *
 * @throws JoseParseError if the JWT is not well-formed.
 * @throws JoseValidationError if the header or payload does not validate.
 */
export function decodeJwt<
  HeaderSchema extends BaseSchema | undefined = undefined,
  PayloadSchema extends BaseSchema | undefined = undefined,
>(options: DecodeJwtOptions<HeaderSchema, PayloadSchema>): DecodeJwtResult<HeaderSchema, PayloadSchema> {
  const jws = parseJws({
    jws: options.jwt,
    protectedHeaderSchema: options.headerSchema,
    understoodCriticalParameters: options.understoodCriticalParameters,
  })

  // RFC 7519 defines the claims set as base64url encoded JSON, so RFC 7797's unencoded payload is
  // not a JWT. Allowing it would mean a token whose claims are not where a JWT's claims are.
  if (jws.registeredProtectedHeader.b64 === false) {
    throw new JoseNotSupportedError(
      `Unable to decode the JWT, its header sets 'b64' to false. An unencoded payload is not valid for a JWT.`
    )
  }

  if (jws.encodedPayload === '') {
    throw new JoseParseError('Unable to decode the JWT, it does not contain a payload')
  }

  const payloadJson = decodeBase64UrlJsonObject(jws.encodedPayload, 'JWT payload')

  // Always validated against the registered claims, and only then against the caller's schema: a
  // schema describing a profile's own claims must not be able to leave `exp` unchecked as a number.
  const registeredPayload = parseWithErrorHandling(zJwtPayload, payloadJson, 'Invalid JWT payload', JoseValidationError)
  const payload = parseWithErrorHandling(
    options.payloadSchema ?? zJwtPayload,
    payloadJson,
    'Invalid JWT payload',
    JoseValidationError
  )

  return {
    header: jws.protectedHeader as InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>,
    payload: payload as InferSchemaOrDefaultOutput<PayloadSchema, typeof zJwtPayload>,
    registeredHeader: jws.registeredProtectedHeader,
    registeredPayload,
    payloadBytes: jws.payload,
    signature: jws.signature,
    signingInput: jws.signingInput,
    compact: options.jwt,
  }
}

export interface DecodeJwtHeaderOptions<HeaderSchema extends BaseSchema | undefined> {
  /** The compact encoded JWT or JWE. */
  jwt: string

  /**
   * Schema to validate the header with, on top of {@link zJwtHeader} — and {@link zJweHeader} for a
   * JWE — which are always applied.
   */
  headerSchema?: HeaderSchema
}

/**
 * Decodes and validates only the header of a compact JWT or JWE.
 *
 * Useful when the header decides what to do next — which key to look up, or how to decrypt — and the
 * rest of the token cannot be read yet.
 *
 * @throws JoseParseError if the token is not well-formed.
 * @throws JoseValidationError if the header does not validate.
 */
export function decodeJwtHeader<HeaderSchema extends BaseSchema | undefined = undefined>(
  options: DecodeJwtHeaderOptions<HeaderSchema>
): { header: InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader> } {
  const parts = options.jwt.split('.')

  // Three parts for a JWS, five for a JWE.
  if (parts.length !== 3 && parts.length !== 5) {
    throw new JoseParseError(
      'Unable to decode the header, the token is neither a compact JWS (three parts) nor a compact JWE (five parts)'
    )
  }

  const headerJson = decodeBase64UrlJsonObject(parts[0], 'header')

  // Always validated against the registered header parameters, and only then against the caller's
  // schema, the way `decodeJwt` validates a header: a schema of the caller's must not be able to let
  // `alg: none` or a private `jwk` through. A JWE is held to the JWE header parameters as well, which
  // require `enc` and an `epk` that is a public key.
  const registeredHeader = parseWithErrorHandling(zJwtHeader, headerJson, 'Invalid header', JoseValidationError)
  if (parts.length === 5) parseWithErrorHandling(zJweHeader, headerJson, 'Invalid JWE header', JoseValidationError)
  const header = options.headerSchema
    ? parseWithErrorHandling(options.headerSchema, headerJson, 'Invalid header', JoseValidationError)
    : registeredHeader

  return { header: header as InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader> }
}
