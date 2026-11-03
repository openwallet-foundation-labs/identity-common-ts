import { z } from 'zod'

export const zTrustMarkIssuer = z.record(z.string(), z.array(z.string()))

export type TrustMarkIssuer = z.input<typeof zTrustMarkIssuer>
