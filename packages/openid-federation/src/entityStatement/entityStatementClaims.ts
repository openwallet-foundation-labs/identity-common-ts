import { z } from 'zod'
import { zConstraint } from '../constraints'
import { zJsonWebKeySet } from '../jsonWeb'
import { zMetadata, zMetadataPolicy } from '../metadata'
import { zTrustMark, zTrustMarkIssuer, zTrustMarkOwner } from '../trustMark'
import { zDate, zHttpsUrl } from '../utils'

export const zEntityStatementClaims = z
  .object({
    iss: z.string(),
    sub: z.string(),
    iat: zDate,
    exp: zDate,
    jwks: zJsonWebKeySet,
    authority_hints: z.array(zHttpsUrl).optional(),
    metadata: zMetadata.optional(),
    metadata_policy: z.record(z.string(), z.record(z.string(), zMetadataPolicy.optional())).optional(),
    constraints: zConstraint.optional(),
    crit: z.array(z.string()).optional(),
    metadata_policy_crit: z.array(z.string()).optional(),
    trust_marks: z.array(zTrustMark).optional(),
    trust_mark_issuers: zTrustMarkIssuer.optional(),
    trust_mark_owners: zTrustMarkOwner.optional(),
    source_endpoint: z.url().optional(),
  })
  .superRefine((data, ctx) => {
    const keyIds = data.jwks.keys.map((key) => key.kid)
    if (keyIds.some((key, i) => keyIds.indexOf(key) !== i)) {
      ctx.addIssue({
        code: 'custom',
        message: 'keys include duplicate key ids',
        path: ['jwks', 'keys'],
      })
    }
  })

export type EntityStatementClaimsOptions = z.input<typeof zEntityStatementClaims>

export type EntityStatementClaims = z.output<typeof zEntityStatementClaims>

export type EntityStatementChain = Array<EntityStatementClaims>
