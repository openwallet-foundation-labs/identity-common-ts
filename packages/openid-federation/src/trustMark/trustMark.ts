import { z } from 'zod'
import { jsonWebTokenSchema } from '../jsonWeb'
import { dateSchema } from '../utils'

/**
 *
 * {@link https://openid.net/specs/openid-federation-1_0.html#section-7.1 | Trust Mark Claims}
 *
 */
export const trustMarkClaimsSchema = z
  .object({
    iss: z.string(),
    sub: z.string(),
    trust_mark_type: z.string(),
    iat: dateSchema,
    exp: dateSchema.optional(),
    logo_uri: z.url().optional(),
    ref: z.url().optional(),
    delegation: z.string().optional(),
  })
  .loose()

/**
 *
 * An entry of the `trust_marks` claim of an entity configuration
 *
 * {@link https://openid.net/specs/openid-federation-1_0.html#section-3.1.1 | trust_marks}
 *
 */
export const trustMarkSchema = z
  .object({
    trust_mark_type: z.string(),
    trust_mark: jsonWebTokenSchema({
      claimsSchema: trustMarkClaimsSchema,
    }),
  })
  .refine((entry) => entry.trust_mark_type === entry.trust_mark.claims.trust_mark_type, {
    message: 'trust_mark_type must be the trust_mark_type of the trust mark JWT',
    path: ['trust_mark_type'],
  })

export type TrustMark = z.output<typeof trustMarkSchema>
