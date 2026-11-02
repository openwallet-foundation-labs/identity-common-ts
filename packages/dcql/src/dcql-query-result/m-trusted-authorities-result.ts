import { z } from 'zod'
import { zIssues, zNonEmptyArray } from '../u-dcql.js'

export namespace DcqlTrustedAuthoritiesResult {
  export const zTrustedAuthorityEntrySuccessResult = z.object({
    success: z.literal(true),
    trusted_authority_index: z.number(),

    // We map from values (multiple options for a credential/query) to value (the matching option)
    output: z.object({
      type: z.enum(['aki', 'etsi_tl', 'openid_federation']),
      value: z.string(),
    }),
  })

  export const zTrustedAuthorityEntryFailureResult = z.object({
    success: z.literal(false),
    trusted_authority_index: z.number(),
    issues: zIssues,
  })

  export const zTrustedAuthoritySuccessResult = z.union([
    // In this case there is no trusted authority on the query
    z.object({
      success: z.literal(true),
      valid_trusted_authority: z.undefined().optional(),
      failed_trusted_authorities: z.undefined().optional(),
    }),
    z.object({
      success: z.literal(true),
      valid_trusted_authority: zTrustedAuthorityEntrySuccessResult,
      failed_trusted_authorities: zNonEmptyArray(zTrustedAuthorityEntryFailureResult).optional(),
    }),
  ])

  export const zTrustedAuthorityFailureResult = z.object({
    success: z.literal(false),
    valid_trusted_authority: z.undefined().optional(),
    failed_trusted_authorities: zNonEmptyArray(zTrustedAuthorityEntryFailureResult),
  })

  export const zModel = z.union([...zTrustedAuthoritySuccessResult.options, zTrustedAuthorityFailureResult])
  export type Input = z.input<typeof zModel>
  export type Output = z.output<typeof zModel>
}
export type DcqlTrustedAuthoritiesResult = DcqlTrustedAuthoritiesResult.Output
