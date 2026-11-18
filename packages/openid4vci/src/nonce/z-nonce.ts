import { zInteger } from '@openid4vc/utils'
import { zNonEmptyString } from '@owf/identity-common'
import z from 'zod'

export const zNonceResponse = z
  .object({
    c_nonce: zNonEmptyString,
    c_nonce_expires_in: z.optional(zInteger),
  })
  .loose()
export type NonceResponse = z.infer<typeof zNonceResponse>
