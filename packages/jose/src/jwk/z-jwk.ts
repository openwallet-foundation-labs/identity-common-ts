import { addValidationIssue, zNonEmptyString } from '@owf/identity-common'
import z from 'zod'
import { zX5c } from './z-x5c'

/**
 * The JWK members that hold private or symmetric key material. `k` is the whole secret of an `oct` key.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-6
 */
export const jwkPrivateMembers = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const

/**
 * A JSON Web Key. Only `kty` is required, as in RFC 7517. Loose, so unknown members survive when the
 * JWK is serialized again, e.g. into a `cnf` claim or a `jwk` header.
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
 * A JWK without private or symmetric key material. Use it for keys from untrusted input, such as a
 * `jwk` header, a `cnf` claim or a fetched JWK Set.
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
