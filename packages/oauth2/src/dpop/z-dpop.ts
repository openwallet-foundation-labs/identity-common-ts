import { zHttpMethod, zHttpsUrl } from '@openid4vc/utils'
import { zNonEmptyString, zNumericDate, zTyp } from '@owf/identity-common'
import { zJwk, zJwtHeader, zJwtPayload } from '@owf/jose'
import z from 'zod'

export const zDpopJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    iat: zNumericDate,
    htu: zHttpsUrl,
    htm: zHttpMethod,
    jti: zNonEmptyString,

    // Only required when presenting in combination with access token
    ath: z.optional(zNonEmptyString),
  })
  .loose()
export type DpopJwtPayload = z.infer<typeof zDpopJwtPayload>

export const zDpopJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: zTyp('dpop+jwt'),
    jwk: zJwk,
  })
  .loose()
export type DpopJwtHeader = z.infer<typeof zDpopJwtHeader>
