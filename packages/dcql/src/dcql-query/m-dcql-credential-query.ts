import { z } from 'zod'
import {
  addDcqlIssue,
  DCQL_VALIDATION_CODES,
  isObject,
  parseWithIssues,
  zEither,
  zIdString,
  zNonEmptyArray,
} from '../u-dcql.js'
import { DcqlClaimsQuery } from './m-dcql-claims-query.js'
import { DcqlTrustedAuthoritiesQuery } from './m-dcql-trusted-authorities.js'

const formatDescription = 'REQUIRED. A string that specifies the format of the requested Verifiable Credential.'
const claimsDescription = 'OPTIONAL. A non-empty array of objects as that specifies claims in the requested Credential.'
const metaDescription =
  'OPTIONAL. An object defining additional properties requested by the Verifier that apply to the metadata and validity data of the Credential.'

function checkClaimIds(credentialQuery: { claims?: { id?: string }[]; claim_sets?: string[][] }, ctx: z.RefinementCtx) {
  // OpenID4VP 1.0 Section 6.3: the id is REQUIRED if claim_sets is present, and the same id MUST NOT be present
  // more than once within the claims array
  const claimIds = new Set<string>()
  credentialQuery.claims?.forEach(({ id }, index) => {
    if (id === undefined) {
      if (credentialQuery.claim_sets) {
        addDcqlIssue(ctx, {
          code: 'missing',
          path: ['claims', index, 'id'],
          message: 'A claim needs an id when the credential query has claim_sets',
        })
      }
      return
    }
    if (claimIds.has(id)) {
      addDcqlIssue(ctx, {
        code: DCQL_VALIDATION_CODES.DUPLICATE_CLAIM_ID,
        path: ['claims', index, 'id'],
        message: `The claim id '${id}' is present more than once in claims`,
      })
    }
    claimIds.add(id)
  })

  // OpenID4VP 1.0 Section 6.1: claim_sets contain identifiers for elements in claims
  credentialQuery.claim_sets?.forEach((claimSet, claimSetIndex) => {
    claimSet.forEach((claimId, index) => {
      if (claimIds.has(claimId)) return
      addDcqlIssue(ctx, {
        code: DCQL_VALIDATION_CODES.UNKNOWN_CLAIM_ID,
        path: ['claim_sets', claimSetIndex, index],
        message: `Claim set ${claimSetIndex} refers to the claim id '${claimId}', which is not in claims`,
      })
    })
  })
}

/**
 * A Credential Query is an object representing a request for a presentation of one Credential.
 */
export namespace DcqlCredentialQuery {
  const zBase = z.object({
    id: zIdString.describe(
      `REQUIRED. A string identifying the Credential in the response and, if provided, the constraints in 'credential_sets'.`
    ),
    require_cryptographic_holder_binding: z
      .boolean()
      .default(true)
      .describe(
        'OPTIONAL. A boolean which indicates whether the Verifier requires a Cryptographic Holder Binding proof. The default value is true, i.e., a Verifiable Presentation with Cryptographic Holder Binding is required. If set to false, the Verifier accepts a Credential without Cryptographic Holder Binding proof.'
      ),
    multiple: z
      .boolean()
      .default(false)
      .describe(
        'OPTIONAL. A boolean which indicates whether multiple Credentials can be returned for this Credential Query. If omitted, the default value is false.'
      ),
    claim_sets: zNonEmptyArray(zNonEmptyArray(zIdString))
      .optional()
      .describe(
        `OPTIONAL. A non-empty array containing arrays of identifiers for elements in 'claims' that specifies which combinations of 'claims' for the Credential are requested.`
      ),
    trusted_authorities: zNonEmptyArray(DcqlTrustedAuthoritiesQuery.zModel)
      .optional()
      .describe(
        'OPTIONAL. A non-empty array of objects as defined in Section 6.1.1 that specifies expected authorities or trust frameworks that certify Issuers, that the Verifier will accept. Every Credential returned by the Wallet SHOULD match at least one of the conditions present in the corresponding trusted_authorities array if present.'
      ),
  })

  export const zMdoc = zBase.extend({
    format: z.literal('mso_mdoc').describe(formatDescription),
    claims: zNonEmptyArray(DcqlClaimsQuery.zMdoc).optional().describe(claimsDescription),
    meta: z
      .object({
        doctype_value: z
          .string()
          .optional()
          .describe(
            'OPTIONAL. String that specifies an allowed value for the doctype of the requested Verifiable Credential.'
          ),
      })
      .optional()
      .describe(metaDescription),
  })
  export type Mdoc = z.output<typeof zMdoc>

  export const zSdJwtVc = zBase.extend({
    format: z.enum(['vc+sd-jwt', 'dc+sd-jwt']).describe(formatDescription),
    claims: zNonEmptyArray(DcqlClaimsQuery.zW3cSdJwtVc).optional().describe(claimsDescription),
    meta: z
      .object({
        // OpenID4VP 1.0 Appendix B.3.5 requires a non-empty array, the drafts did not say
        vct_values: zNonEmptyArray(z.string())
          .optional()
          .describe(
            'OPTIONAL. A non-empty array of strings that specifies allowed values for the type of the requested Verifiable Credential.'
          ),
      })
      .optional()
      .describe(metaDescription),
  })
  export type SdJwtVc = z.output<typeof zSdJwtVc>

  export const zW3cVc = zBase.extend({
    format: z.enum(['jwt_vc_json', 'ldp_vc', 'vc+sd-jwt']).describe(formatDescription),
    claims: zNonEmptyArray(DcqlClaimsQuery.zW3cSdJwtVc).optional().describe(claimsDescription),
    meta: z
      .object({
        type_values: zNonEmptyArray(zNonEmptyArray(z.string())).describe(
          'REQUIRED. An array of string arrays that specifies the fully expanded types (IRIs) after the @context was applied that the Verifier accepts to be presented in the Presentation. Each of the top-level arrays specifies one alternative to match the type values of the Verifiable Credential against. Each inner array specifies a set of fully expanded types that MUST be present in the type property of the Verifiable Credential, regardless of order or the presence of additional types.'
        ),
      })
      .describe(
        'REQUIRED. An object defining additional properties requested by the Verifier that apply to the metadata and validity data of the Credential.'
      ),
  })
  export type W3cVc = z.output<typeof zW3cVc>

  export const zModel = z
    .discriminatedUnion(
      'format',
      [
        zMdoc,
        zW3cVc.extend({ format: z.enum(['jwt_vc_json', 'ldp_vc']).describe(formatDescription) }),
        zSdJwtVc.extend({ format: z.literal('dc+sd-jwt').describe(formatDescription) }),
        // vc+sd-jwt is a W3C VC format and the SD-JWT VC format before dc+sd-jwt. The two queries differ in meta only.
        zSdJwtVc.extend({
          format: z.literal('vc+sd-jwt').describe(formatDescription),
          meta: zEither(
            (meta) => isObject(meta) && 'type_values' in meta,
            zW3cVc.shape.meta,
            zSdJwtVc.shape.meta
          ).optional(),
        }),
      ],
      { error: `Expected format to be one of 'mso_mdoc', 'dc+sd-jwt', 'vc+sd-jwt', 'jwt_vc_json' or 'ldp_vc'` }
    )
    .superRefine(checkClaimIds)
  export type Input = z.input<typeof zModel>
  export type Output = z.output<typeof zModel>

  /**
   * @deprecated `zModel` checks that the claim sets only refer to claims of the query.
   * @throws {DcqlParseError} with the `issues` of the credential query
   */
  export const validate = (credentialQuery: Output) => {
    parseWithIssues(zModel, credentialQuery, 'DCQL credential query')
  }
}
export type DcqlCredentialQuery = DcqlCredentialQuery.Output
