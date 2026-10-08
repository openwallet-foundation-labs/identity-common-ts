import { base64url, stringToBytes } from '@owf/identity-common'
import z from 'zod'
import type { HashAlgorithm, HashCallback } from '../hash'
import { parseWithErrorHandling } from '../utils/zod'
import type { Jwk } from './z-jwk'

/**
 * The members that make up the thumbprint of a JWK, per key type, in the lexicographic order
 * RFC 7638 requires.
 *
 * The thumbprint is computed over exactly these members and nothing else, so that two JWKs
 * representing the same key — regardless of which optional members they carry, or in what order —
 * hash to the same value.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7638#section-3.2
 */
export const zJwkThumbprintComponents = z
  .discriminatedUnion('kty', [
    z.object({
      kty: z.literal('EC'),
      crv: z.string(),
      x: z.string(),
      y: z.string(),
    }),
    z.object({
      kty: z.literal('OKP'),
      crv: z.string(),
      x: z.string(),
    }),
    z.object({
      kty: z.literal('RSA'),
      e: z.string(),
      n: z.string(),
    }),
    z.object({
      kty: z.literal('oct'),
      k: z.string(),
    }),
  ])
  .transform((jwk) => {
    // The members are written out per key type rather than sorted generically, so the order is
    // visible here and cannot drift from the order RFC 7638 prescribes.
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

  /** The hash callback used to compute the digest. */
  hashCallback: HashCallback
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
    `Unable to calculate the thumbprint of the jwk. Either the 'kty' is not supported, or a member required for the thumbprint is missing`
  )

  return base64url.encode(await options.hashCallback(stringToBytes(JSON.stringify(components)), options.hashAlgorithm))
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
