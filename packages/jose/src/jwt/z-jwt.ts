import { addValidationIssue, zBase64Url, zNonEmptyString, zNumericDate } from '@owf/identity-common'
import z from 'zod'
import { zPublicJwk } from '../jwk/z-jwk'
import { zJwsProtectedHeader } from '../jws/z-jws'
import { zCompactSerialization, zStringOrUri } from '../utils/z-common'

/**
 * The header of a JWT, which is a JWS protected header.
 *
 * Compose on top of it to require what a token type needs, in particular its `typ`:
 *
 * ```ts
 * const zKbJwtHeader = z.object({ ...zJwtHeader.shape, typ: zTyp('kb+jwt') }).loose()
 * ```
 */
export const zJwtHeader = zJwsProtectedHeader

export type JwtHeader = z.infer<typeof zJwtHeader>

/** The `cnf` members that each name the key, of which a `cnf` has at most one. */
const confirmationKeyMembers = ['jwk', 'jwe', 'jku', 'jkt'] as const

/**
 * The `cnf` (confirmation) claim, which names the one key a token is bound to.
 *
 * The key is named in one way only, so that every verifier binds the token to the same key:
 * - at most one of `jwk`, `jwe`, `jku` (RFC 7800 section 3.1) and `jkt` (RFC 9449)
 * - `kid` on its own, e.g. a DID URL, or with `jku` to select the key from the set (RFC 7800
 *   section 3.5) or with `jkt` that the key it resolves to has to match. Not with `jwk` or `jwe`,
 *   which carry the key itself, and with it its `kid`.
 *
 * A token bound to several keys carries the others in claims of its own.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7800#section-3.1
 */
export const zJwtConfirmation = z
  .object({
    /** The public key the token is bound to. */
    jwk: zPublicJwk.optional(),

    /** The JWK thumbprint of the key the token is bound to, e.g. of a DPoP key. */
    jkt: zBase64Url.min(1).optional(),

    /** A key id, to be resolved by the recipient. */
    kid: zNonEmptyString.optional(),
  })
  .loose()
  .superRefine((cnf, ctx) => {
    const keyMembers = confirmationKeyMembers.filter((member) => cnf[member] !== undefined)
    for (const member of keyMembers.slice(1)) {
      addValidationIssue(ctx, {
        code: 'not_allowed',
        path: [member],
        message: `The cnf claim names its key with '${keyMembers[0]}', so it may not also have '${member}'`,
      })
    }

    if (cnf.kid !== undefined && (cnf.jwk !== undefined || cnf.jwe !== undefined)) {
      addValidationIssue(ctx, {
        code: 'not_allowed',
        path: ['kid'],
        message: `The cnf claim carries its key in '${cnf.jwk !== undefined ? 'jwk' : 'jwe'}', so it may not also have a 'kid'`,
      })
    }
  })

export type JwtConfirmation = z.infer<typeof zJwtConfirmation>

/**
 * The claims registered for a JWT.
 *
 * All of them are optional, as RFC 7519 requires none: which claims a token must carry follows from
 * the token type, and is expressed by composing on this schema and by `requiredClaims` at
 * verification time.
 *
 * The schema is loose, so claims that are not registered are carried through unvalidated.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7519#section-4.1
 */
export const zJwtPayload = z
  .object({
    iss: zStringOrUri.optional(),
    sub: zStringOrUri.optional(),
    aud: z.union([zStringOrUri, z.array(zStringOrUri)]).optional(),
    exp: zNumericDate.optional(),
    nbf: zNumericDate.optional(),
    iat: zNumericDate.optional(),
    jti: zNonEmptyString.optional(),

    /** Not registered by RFC 7519, but used the same way across OpenID Connect and OAuth 2.0. */
    nonce: zNonEmptyString.optional(),

    cnf: zJwtConfirmation.optional(),

    /** Reserved for the Token Status List. @see https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list */
    status: z.record(z.string(), z.unknown()).optional(),

    /** Reserved for OpenID Federation. */
    trust_chain: z.tuple([zNonEmptyString], zNonEmptyString).optional(),
  })
  .loose()

export type JwtPayload = z.infer<typeof zJwtPayload>

/**
 * A JWT in compact serialization.
 *
 * Unlike `zCompactJws` the payload part may not be empty: a JWT carries its claims set, so a
 * detached payload is not a JWT.
 */
export const zCompactJwt = zCompactSerialization('jwt', 3)
