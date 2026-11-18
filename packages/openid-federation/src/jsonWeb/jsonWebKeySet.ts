import { z } from 'zod'
import { zJsonWebKey } from './jsonWebKey'

export const zJsonWebKeySet = z.object({
  keys: z.array(zJsonWebKey),
})

export type JsonWebKeySetOptions = z.input<typeof zJsonWebKeySet>

export type JsonWebKeySet = z.output<typeof zJsonWebKeySet>
