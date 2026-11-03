import { zNonEmptyString, zNumericDate, zTyp } from '@owf/identity-common'
import { zJwtHeader, zJwtPayload } from '@owf/jose'
import z from 'zod'

export const zAccessTokenProfileJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: zTyp('at+jwt'),
  })
  .loose()
export type AccessTokenProfileJwtHeader = z.infer<typeof zAccessTokenProfileJwtHeader>

export const zAccessTokenProfileJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    iss: zNonEmptyString,
    exp: zNumericDate,
    iat: zNumericDate,
    aud: z.union([zNonEmptyString, z.array(zNonEmptyString)]),
    sub: zNonEmptyString,

    // REQUIRED according to RFC 9068, but OpenID4VCI allows anonymous access
    client_id: z.optional(zNonEmptyString),
    jti: zNonEmptyString,

    // SHOULD be included in the authorization request contained it
    scope: z.optional(zNonEmptyString),
  })
  .loose()

export type AccessTokenProfileJwtPayload = z.infer<typeof zAccessTokenProfileJwtPayload>
