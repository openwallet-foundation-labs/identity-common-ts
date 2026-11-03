import { addValidationIssue, zBase64Url, zNonEmptyString } from '@owf/identity-common'
import z from 'zod'
import { zJwsAlg } from '../jwa/z-alg'
import { zPublicJwk } from '../jwk/z-jwk'
import { zX5c } from '../jwk/z-x5c'

/**
 * The registered JWS header parameters. Loose, so the parameters of a profile survive. Compose on top
 * of it to require the parameters a profile needs:
 *
 * ```ts
 * const zMyHeader = z.object({ ...zJwsProtectedHeader.shape, typ: zTyp('my+jwt') }).loose()
 * ```
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1
 */
export const zJwsProtectedHeader = z
  .object({
    alg: zJwsAlg,

    typ: zNonEmptyString.optional(),
    cty: zNonEmptyString.optional(),

    kid: zNonEmptyString.optional(),
    jwk: zPublicJwk.optional(),
    jku: zNonEmptyString.optional(),

    x5c: zX5c.optional(),
    x5u: zNonEmptyString.optional(),
    x5t: zBase64Url.min(1).optional(),
    'x5t#S256': zBase64Url.min(1).optional(),

    /**
     * The header parameters a recipient must understand. Validated further in `assertCriticalHeaderParameters`.
     *
     * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11
     */
    crit: z.array(zNonEmptyString).min(1).optional(),

    /**
     * Whether the payload is base64url encoded. `false` means it is carried and signed as it is.
     *
     * @see https://www.rfc-editor.org/rfc/rfc7797
     */
    b64: z.boolean().optional(),

    /**
     * The OpenID Federation trust chain that establishes the signer.
     *
     * @see https://openid.net/specs/openid-federation-1_0.html
     */
    trust_chain: z.tuple([zNonEmptyString], zNonEmptyString).optional(),
  })
  .loose()

export type JwsProtectedHeader = z.infer<typeof zJwsProtectedHeader>

/**
 * A JWS unprotected header. Untyped: it is not covered by the signature, so the library reads nothing
 * from it. A profile that needs a parameter, as JAdES does `etsiU`, validates it itself.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-7.2
 */
export const zJwsUnprotectedHeader = z.record(z.string(), z.unknown())

export type JwsUnprotectedHeader = z.infer<typeof zJwsUnprotectedHeader>

/**
 * A JWS in compact serialization. An empty payload part is a detached payload. A JWS with an unencoded
 * payload (`b64: false`) does not match, but `parseJws` accepts it.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-7.1
 */
export const zCompactJws = z.string().superRefine((jws, ctx) => {
  const parts = jws.split('.')
  const isCompactJws =
    parts.length === 3 &&
    parts[0] !== '' &&
    parts[2] !== '' &&
    parts.every((part) => zBase64Url.safeParse(part).success)

  if (!isCompactJws) {
    addValidationIssue(ctx, { code: 'invalid_format', message: 'Not a valid compact JWS', context: { format: 'jws' } })
  }
})

/** The signature of a JSON serialized JWS. Never empty: that is an unsecured JWS. */
const zJwsSignature = zBase64Url.min(1, { message: 'Expected a signature, an unsecured JWS is not supported' })

/**
 * A JWS in flattened JSON serialization.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2
 */
export const zFlattenedJws = z
  .object({
    /** Absent for a detached payload. Not `zBase64Url`, as it is unencoded when `b64` is false. */
    payload: z.string().optional(),
    protected: zBase64Url.optional(),
    header: zJwsUnprotectedHeader.optional(),
    signature: zJwsSignature,
  })
  .loose()

export type FlattenedJws = z.infer<typeof zFlattenedJws>

/**
 * A JWS in general JSON serialization.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
 */
export const zGeneralJws = z
  .object({
    payload: z.string().optional(),
    signatures: z
      .array(
        z
          .object({
            protected: zBase64Url.optional(),
            header: zJwsUnprotectedHeader.optional(),
            signature: zJwsSignature,
          })
          .loose()
      )
      .min(1),
  })
  .loose()

export type GeneralJws = z.infer<typeof zGeneralJws>
