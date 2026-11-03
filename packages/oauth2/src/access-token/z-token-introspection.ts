import { zNonEmptyString, zNumericDate } from '@owf/identity-common'
import { zJwtConfirmation } from '@owf/jose'
import z from 'zod'

export const zTokenIntrospectionRequest = z
  .object({
    token: zNonEmptyString,
    token_type_hint: z.optional(z.string()),
  })
  .loose()

export type TokenIntrospectionRequest = z.infer<typeof zTokenIntrospectionRequest>

export const zTokenIntrospectionResponse = z
  .object({
    active: z.boolean(),
    scope: z.optional(zNonEmptyString),
    client_id: z.optional(zNonEmptyString),
    username: z.optional(z.string()),
    token_type: z.optional(zNonEmptyString),

    exp: z.optional(zNumericDate),
    iat: z.optional(zNumericDate),
    nbf: z.optional(zNumericDate),

    sub: z.optional(zNonEmptyString),
    aud: z.optional(z.union([zNonEmptyString, z.array(zNonEmptyString)])),

    iss: z.optional(zNonEmptyString),
    jti: z.optional(zNonEmptyString),

    cnf: z.optional(zJwtConfirmation),
  })
  .loose()

export type TokenIntrospectionResponse = z.infer<typeof zTokenIntrospectionResponse>
