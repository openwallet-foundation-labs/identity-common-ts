import { zNumericDate } from '@owf/identity-common'
import z from 'zod'
import { zPublicJwk } from '../jwk/z-jwk'
import { zJwsProtectedHeader } from '../jws/z-jws'
import { zStringOrUri } from '../utils/z-common'

/**
 * The header of a JWT, which is a JWS protected header.
 *
 * Compose on top of it to require what a token type needs, in particular its `typ`:
 *
 * ```ts
 * const zKeyBindingJwtHeader = z.object({ ...zJwtHeader.shape, typ: zJoseType('kb+jwt') }).loose()
 * ```
 */
export const zJwtHeader = zJwsProtectedHeader

export type JwtHeader = z.infer<typeof zJwtHeader>

/**
 * The `cnf` (confirmation) claim, which names the key a token is bound to.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7800#section-3.1
 */
export const zJwtConfirmation = z
  .object({
    /** The public key the token is bound to. */
    jwk: zPublicJwk.optional(),

    /** The JWK thumbprint of the key the token is bound to, e.g. of a DPoP key. */
    jkt: z.string().optional(),

    /** A key id, to be resolved by the recipient. */
    kid: z.string().optional(),
  })
  .loose()

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
    jti: z.string().optional(),

    /** Not registered by RFC 7519, but used the same way across OpenID Connect and OAuth 2.0. */
    nonce: z.string().optional(),

    cnf: zJwtConfirmation.optional(),

    /** Reserved for the Token Status List. @see https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list */
    status: z.record(z.string(), z.unknown()).optional(),

    /** Reserved for OpenID Federation. */
    trust_chain: z.tuple([z.string()], z.string()).optional(),
  })
  .loose()

export type JwtPayload = z.infer<typeof zJwtPayload>

/**
 * A JWT in compact serialization.
 *
 * Unlike `zCompactJws` the payload part may not be empty: a JWT carries its claims set, so a
 * detached payload is not a JWT.
 */
export const zCompactJwt = z.string().regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, {
  message: 'Not a valid compact JWT',
})
