import z from 'zod'
import { zX5c } from './z-x5c'

/**
 * The JWK members that hold private or symmetric key material.
 *
 * `k` is included because an `oct` key is symmetric: the whole key is secret, so a JWK carrying one
 * is never a public key.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-6
 */
export const jwkPrivateMembers = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const

/**
 * A JSON Web Key.
 *
 * Only `kty` is required, as that is all RFC 7517 requires: which other members are present, and
 * what they mean, follows from the key type. The schema is deliberately loose, so that a JWK is
 * carried through with the members it was received with — a JWK is often re-serialized (into a
 * thumbprint, a `cnf` claim, a `jwk` header) and dropping unknown members would change it.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7517#section-4
 */
export const zJwk = z
  .object({
    kty: z.string(),

    // Common parameters
    use: z.string().optional(),
    key_ops: z.array(z.string()).optional(),
    alg: z.string().optional(),
    kid: z.string().optional(),
    x5u: z.string().optional(),
    x5c: zX5c.optional(),
    x5t: z.string().optional(),
    'x5t#S256': z.string().optional(),
    ext: z.boolean().optional(),

    // EC and OKP
    crv: z.string().optional(),
    x: z.string().optional(),
    y: z.string().optional(),

    // RSA
    n: z.string().optional(),
    e: z.string().optional(),

    // Private and symmetric key material
    d: z.string().optional(),
    p: z.string().optional(),
    q: z.string().optional(),
    dp: z.string().optional(),
    dq: z.string().optional(),
    qi: z.string().optional(),
    oth: z
      .array(
        z
          .object({
            r: z.string().optional(),
            d: z.string().optional(),
            t: z.string().optional(),
          })
          .loose()
      )
      .optional(),
    k: z.string().optional(),
  })
  .loose()

export type Jwk = z.infer<typeof zJwk>

/**
 * A JWK that must not carry private or symmetric key material.
 *
 * Use this wherever a key is read from a place an attacker can write — the `jwk` header parameter of
 * a JWS, a `cnf` claim, a fetched JWK Set — so that a private key can never be accepted where a
 * public key is expected, and so that a private key is never accidentally serialized into a token.
 */
export const zPublicJwk = zJwk.superRefine((jwk, ctx) => {
  const privateMembers = jwkPrivateMembers.filter((member) => jwk[member] !== undefined)
  if (privateMembers.length === 0) return

  ctx.addIssue({
    code: 'custom',
    message: `Expected a public jwk, but the jwk contains the private key member(s) ${privateMembers
      .map((member) => `'${member}'`)
      .join(', ')}`,
  })
})

export type PublicJwk = z.infer<typeof zPublicJwk>

/**
 * A JWK Set.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7517#section-5
 */
export const zJwkSet = z.object({ keys: z.array(zJwk) }).loose()

export type JwkSet = z.infer<typeof zJwkSet>

/** A JWK Set whose keys must all be public, see {@link zPublicJwk}. */
export const zPublicJwkSet = z.object({ keys: z.array(zPublicJwk) }).loose()
