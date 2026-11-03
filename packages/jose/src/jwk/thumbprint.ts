import {
  base64url,
  type HashAlgorithm,
  type Hasher,
  parseWithErrorHandling,
  zNonEmptyString,
} from '@owf/identity-common'
import z from 'zod'
import { JoseValidationError } from '../error'
import type { Jwk } from './z-jwk'

/**
 * The required members of a JWK per key type, in the lexicographic order RFC 7638 requires.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7638#section-3.2
 */
export const zJwkThumbprintComponents = z
  .discriminatedUnion('kty', [
    z.object({
      kty: z.literal('EC'),
      crv: zNonEmptyString,
      x: zNonEmptyString,
      y: zNonEmptyString,
    }),
    z.object({
      kty: z.literal('OKP'),
      crv: zNonEmptyString,
      x: zNonEmptyString,
    }),
    z.object({
      kty: z.literal('RSA'),
      e: zNonEmptyString,
      n: zNonEmptyString,
    }),
    z.object({
      kty: z.literal('oct'),
      k: zNonEmptyString,
    }),
  ])
  .transform((jwk) => {
    if (jwk.kty === 'EC') return { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
    if (jwk.kty === 'OKP') return { crv: jwk.crv, kty: jwk.kty, x: jwk.x }
    if (jwk.kty === 'RSA') return { e: jwk.e, kty: jwk.kty, n: jwk.n }
    return { k: jwk.k, kty: jwk.kty }
  })

export interface CalculateJwkThumbprintOptions {
  /** The jwk to calculate the thumbprint for. */
  jwk: Jwk

  /** The hashing algorithm to use. RFC 7638 registers SHA-256 as the default. */
  hashAlgorithm: HashAlgorithm

  /** The hash callback used to compute the digest, e.g. `hasher` of `@owf/crypto`. */
  hashCallback: Hasher
}

/**
 * Calculates the JWK thumbprint of a key: the base64url encoded digest over the required members of
 * the key, serialized as JSON with lexicographically ordered member names and no whitespace.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7638
 */
export async function calculateJwkThumbprint(options: CalculateJwkThumbprintOptions): Promise<string> {
  const components = parseWithErrorHandling(
    zJwkThumbprintComponents,
    options.jwk,
    `Unable to calculate the thumbprint of the jwk. Either the 'kty' is not supported, or a member required for the thumbprint is missing`,
    JoseValidationError
  )

  return base64url.encode(await options.hashCallback(JSON.stringify(components), options.hashAlgorithm))
}

/**
 * Calculates the JWK thumbprint URI of a key: `urn:ietf:params:oauth:jwk-thumbprint:<hash>:<thumbprint>`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9278
 */
export async function calculateJwkThumbprintUri(options: CalculateJwkThumbprintOptions): Promise<string> {
  const thumbprint = await calculateJwkThumbprint(options)
  return `urn:ietf:params:oauth:jwk-thumbprint:${options.hashAlgorithm}:${thumbprint}`
}
