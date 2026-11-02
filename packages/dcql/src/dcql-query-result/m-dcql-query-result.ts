import { z } from 'zod'
import { DcqlCredentialQuery } from '../dcql-query/m-dcql-credential-query.js'
import { CredentialSetQuery } from '../dcql-query/m-dcql-credential-set-query.js'
import { zIdString, zNonEmptyArray } from '../u-dcql.js'
import { DcqlClaimsResult } from './m-claims-result.js'
import { DcqlMetaResult } from './m-meta-result.js'
import { DcqlTrustedAuthoritiesResult } from './m-trusted-authorities-result.js'

export namespace DcqlQueryResult {
  export const zCredentialQueryItemCredentialSuccessResult = z.object({
    success: z.literal(true),
    input_credential_index: z.number(),
    trusted_authorities: DcqlTrustedAuthoritiesResult.zTrustedAuthoritySuccessResult,

    // TODO: format specific (we should probably add format to this object, to differentiate?)
    claims: DcqlClaimsResult.zClaimsSuccessResult,
    meta: DcqlMetaResult.zMetaSuccessResult,
  })

  export const zCredentialQueryItemCredentialFailureResult = z.object({
    success: z.literal(false),
    input_credential_index: z.number(),
    trusted_authorities: DcqlTrustedAuthoritiesResult.zModel,
    claims: DcqlClaimsResult.zModel,
    meta: DcqlMetaResult.zModel,
  })

  export const zCredentialQueryItemResult = z.union([
    z.object({
      success: z.literal(true),
      credential_query_id: zIdString,
      valid_credentials: zNonEmptyArray(zCredentialQueryItemCredentialSuccessResult),
      failed_credentials: zNonEmptyArray(zCredentialQueryItemCredentialFailureResult).optional(),
    }),
    z.object({
      success: z.literal(false),
      credential_query_id: zIdString,
      valid_credentials: z.undefined().optional(),
      failed_credentials: zNonEmptyArray(zCredentialQueryItemCredentialFailureResult).optional(),
    }),
  ])

  export const zCredentialQueryResult = z.record(zIdString, zCredentialQueryItemResult)

  export type CredentialQueryResult = z.output<typeof zCredentialQueryResult>
  export type CredentialQueryItemResult = z.output<typeof zCredentialQueryItemResult>
  export type CredentialQueryItemCredentialSuccessResult = z.output<typeof zCredentialQueryItemCredentialSuccessResult>
  export type CredentialQueryItemCredentialFailureResult = z.output<typeof zCredentialQueryItemCredentialFailureResult>

  export const zModel = z.object({
    credentials: zNonEmptyArray(DcqlCredentialQuery.zModel).describe(
      'REQUIRED. A non-empty array of Credential Queries that specify the requested Verifiable Credentials.'
    ),

    credential_matches: zCredentialQueryResult,

    credential_sets: zNonEmptyArray(
      CredentialSetQuery.zModel.extend({
        matching_options: z.union([z.undefined(), zNonEmptyArray(z.array(z.string()))]),
      })
    )
      .optional()
      .describe(
        'OPTIONAL. A non-empty array of credential set queries that specifies additional constraints on which of the requested Verifiable Credentials to return.'
      ),

    can_be_satisfied: z.boolean(),
  })
  export type Input = z.input<typeof zModel>
  export type Output = z.output<typeof zModel>

  export type CredentialMatch = Input['credential_matches'][number]
  export type CredentialMatchRecord = Input['credential_matches']
}
export type DcqlQueryResult = DcqlQueryResult.Output
