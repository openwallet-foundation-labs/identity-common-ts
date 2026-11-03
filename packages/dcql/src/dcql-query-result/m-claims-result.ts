import { z } from 'zod'
import { zIdString, zIssues, zNonEmptyArray } from '../u-dcql.js'
import { DcqlMdocCredential, DcqlSdJwtVcCredential, DcqlW3cVcCredential } from '../u-dcql-credential.js'

export namespace DcqlClaimsResult {
  const zClaimsOutput = z.union([
    DcqlMdocCredential.zModel.shape.namespaces,
    DcqlSdJwtVcCredential.zModel.shape.claims,
    DcqlW3cVcCredential.zModel.shape.claims,
  ])
  export type ClaimsOutput = z.output<typeof zClaimsOutput>

  export const zClaimsEntrySuccessResult = z.object({
    success: z.literal(true),
    claim_index: z.number(),
    claim_id: zIdString.optional(),
    output: zClaimsOutput,
  })

  export const zClaimsEntryFailureResult = z.object({
    success: z.literal(false),
    claim_index: z.number(),
    claim_id: zIdString.optional(),

    issues: zIssues,
  })

  export const zClaimSetSuccessResult = z.object({
    success: z.literal(true),

    // Undefined in case of no claim set
    claim_set_index: z.union([z.number(), z.undefined()]),

    // We use indexes because if there are no claim sets, the ids can be undefined
    // Can be empty array in case there are no claims
    valid_claim_indexes: zNonEmptyArray(z.number()).optional(),
    failed_claim_indexes: z.undefined().optional(),
    output: zClaimsOutput,
  })

  export const zClaimSetFailureResult = z.object({
    success: z.literal(false),

    // Undefined in case of no claim set
    claim_set_index: z.union([z.number(), z.undefined()]),

    // We use indexes because if there are no claim sets, the ids can be undefined
    valid_claim_indexes: zNonEmptyArray(z.number()).optional(),
    failed_claim_indexes: zNonEmptyArray(z.number()),

    issues: zIssues,
  })

  export const zClaimsSuccessResult = z.object({
    success: z.literal(true),
    valid_claims: zNonEmptyArray(zClaimsEntrySuccessResult).optional(),
    failed_claims: zNonEmptyArray(zClaimsEntryFailureResult).optional(),

    valid_claim_sets: zNonEmptyArray(zClaimSetSuccessResult),
    failed_claim_sets: zNonEmptyArray(zClaimSetFailureResult).optional(),
  })

  export const zClaimsFailureResult = z.object({
    success: z.literal(false),
    valid_claims: zNonEmptyArray(zClaimsEntrySuccessResult).optional(),
    failed_claims: zNonEmptyArray(zClaimsEntryFailureResult),

    valid_claim_sets: z.undefined().optional(),
    failed_claim_sets: zNonEmptyArray(zClaimSetFailureResult),
  })

  export const zModel = z.union([zClaimsSuccessResult, zClaimsFailureResult])
  export type Input = z.input<typeof zModel>
  export type Output = z.output<typeof zModel>
}
export type DcqlClaimsResult = DcqlClaimsResult.Output
