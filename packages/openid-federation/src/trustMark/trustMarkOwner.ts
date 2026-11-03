import { z } from 'zod'
import { zJsonWebKeySet } from '../jsonWeb'

export const zTrustMarkOwner = z.record(
  z.string(),
  z.object({
    sub: z.string(),
    jwks: zJsonWebKeySet,
  })
)

export type TrustMarkOwner = z.input<typeof zTrustMarkOwner>
