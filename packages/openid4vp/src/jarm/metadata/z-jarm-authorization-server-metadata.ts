import { zJwsAlg } from '@owf/jose'
import { z } from 'zod'

export const zJarmServerMetadata = z.object({
  authorization_signing_alg_values_supported: z.array(zJwsAlg),
  authorization_encryption_alg_values_supported: z.array(zJwsAlg),
  authorization_encryption_enc_values_supported: z.array(z.string()),
})

export type JarmServerMetadata = z.infer<typeof zJarmServerMetadata>
