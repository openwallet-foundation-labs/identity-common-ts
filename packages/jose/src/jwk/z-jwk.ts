import { addValidationIssue, zNonEmptyString } from '@owf/identity-common'
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
    kty: zNonEmptyString,

    // Common parameters
    use: zNonEmptyString.optional(),
    key_ops: z.array(zNonEmptyString).optional(),
    alg: zNonEmptyString.optional(),
    kid: zNonEmptyString.optional(),
    x5u: zNonEmptyString.optional(),
    x5c: zX5c.optional(),
    x5t: zNonEmptyString.optional(),
    'x5t#S256': zNonEmptyString.optional(),
    ext: z.boolean().optional(),

    // EC and OKP
    crv: zNonEmptyString.optional(),
    x: zNonEmptyString.optional(),
    y: zNonEmptyString.optional(),

    // RSA
    n: zNonEmptyString.optional(),
    e: zNonEmptyString.optional(),

    // Private and symmetric key material
    d: zNonEmptyString.optional(),
    p: zNonEmptyString.optional(),
    q: zNonEmptyString.optional(),
    dp: zNonEmptyString.optional(),
    dq: zNonEmptyString.optional(),
    qi: zNonEmptyString.optional(),
    oth: z
      .array(
        z
          .object({
            r: zNonEmptyString.optional(),
            d: zNonEmptyString.optional(),
            t: zNonEmptyString.optional(),
          })
          .loose()
      )
      .optional(),
    k: zNonEmptyString.optional(),
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
  for (const member of jwkPrivateMembers) {
    if (jwk[member] === undefined) continue
    addValidationIssue(ctx, {
      code: 'not_allowed',
      path: [member],
      message: `Expected a public jwk, but the jwk contains the private key member '${member}'`,
    })
  }
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
