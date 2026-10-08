import z from 'zod'
import { zJwsAlg } from '../jwa/z-alg'
import { zPublicJwk } from '../jwk/z-jwk'
import { zX5c } from '../jwk/z-x5c'
import { zBase64Url } from '../utils/z-common'

/**
 * The header parameters registered for a JWS.
 *
 * The schema is loose: the registry is open and a JWS profile regularly adds parameters of its own,
 * which have to survive parsing so that the header can be re-serialized unchanged. Compose on top of
 * it to require the parameters a profile needs:
 *
 * ```ts
 * const zMyHeader = z.object({ ...zJwsProtectedHeader.shape, typ: zJoseType('my+jwt') }).loose()
 * ```
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1
 */
export const zJwsProtectedHeader = z
  .object({
    alg: zJwsAlg,

    typ: z.string().optional(),
    cty: z.string().optional(),

    kid: z.string().optional(),
    // A `jwk` in the header is chosen by whoever wrote the token, so it can never carry private key
    // material; see `zPublicJwk`.
    jwk: zPublicJwk.optional(),
    jku: z.string().optional(),

    x5c: zX5c.optional(),
    x5u: z.string().optional(),
    x5t: z.string().optional(),
    'x5t#S256': z.string().optional(),

    /**
     * The header parameters that a recipient must understand to accept the JWS.
     *
     * Validated further in `assertCriticalHeaderParameters`, which is where the rules that need the
     * rest of the header are checked.
     *
     * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11
     */
    crit: z.array(z.string().min(1)).min(1).optional(),

    /**
     * Whether the payload is base64url encoded in the serialization. `false` means the payload is
     * carried and signed as-is.
     *
     * @see https://www.rfc-editor.org/rfc/rfc7797
     */
    b64: z.boolean().optional(),

    /**
     * Reserved for OpenID Federation, which carries the trust chain that establishes the signer in
     * the header rather than resolving it out of band.
     *
     * @see https://openid.net/specs/openid-federation-1_0.html
     */
    trust_chain: z.tuple([z.string()], z.string()).optional(),
  })
  .loose()

export type JwsProtectedHeader = z.infer<typeof zJwsProtectedHeader>

/**
 * A JWS unprotected header, which is not covered by the signature.
 *
 * Nothing is typed here on purpose: a parameter read from the unprotected header is a parameter an
 * attacker can change, so the library never reads one for anything security relevant. A profile that
 * needs to read one (JAdES reads `etsiU`) validates it with a schema of its own.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-7.2
 */
export const zJwsUnprotectedHeader = z.record(z.string(), z.unknown())

export type JwsUnprotectedHeader = z.infer<typeof zJwsUnprotectedHeader>

/**
 * A JWS in compact serialization.
 *
 * The payload part may be empty, which is how a detached payload is carried. This does not match a
 * JWS whose payload is unencoded (RFC 7797 `b64: false`); such a JWS is still accepted by
 * `parseJws`, which reads the header before deciding how to read the payload.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-7.1
 */
export const zCompactJws = z.string().regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+$/, {
  message: 'Not a valid compact JWS',
})

/**
 * The signature of a JWS in a JSON serialization. Never empty: an empty signature is how an unsecured
 * JWS is serialized, and `alg: none` is not accepted anywhere in this package.
 */
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
