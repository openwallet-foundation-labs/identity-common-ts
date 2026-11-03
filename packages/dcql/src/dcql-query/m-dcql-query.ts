import { z } from 'zod'
import { runDcqlQuery } from '../dcql-query-result/run-dcql-query.js'
import { addDcqlIssue, DCQL_VALIDATION_CODES, parseWithIssues, zNonEmptyArray } from '../u-dcql.js'
import type { DcqlCredential } from '../u-dcql-credential.js'
import { DcqlCredentialQuery } from './m-dcql-credential-query.js'
import { CredentialSetQuery } from './m-dcql-credential-set-query.js'

function checkCredentialQueryIds(
  query: { credentials: { id: string }[]; credential_sets?: { options: string[][] }[] },
  ctx: z.RefinementCtx
) {
  // OpenID4VP 1.0 Section 6.1: the same id MUST NOT be present more than once
  const seen = new Set<string>()
  query.credentials.forEach(({ id }, index) => {
    if (seen.has(id)) {
      addDcqlIssue(ctx, {
        code: DCQL_VALIDATION_CODES.DUPLICATE_CREDENTIAL_QUERY_ID,
        path: ['credentials', index, 'id'],
        message: `The credential query id '${id}' is present more than once`,
      })
    }
    seen.add(id)
  })

  // OpenID4VP 1.0 Section 6.2: each option is a list of Credential Query identifiers
  query.credential_sets?.forEach((credentialSet, credentialSetIndex) => {
    credentialSet.options.forEach((option, optionIndex) => {
      option.forEach((id, index) => {
        if (seen.has(id)) return
        addDcqlIssue(ctx, {
          code: DCQL_VALIDATION_CODES.UNKNOWN_CREDENTIAL_QUERY_ID,
          path: ['credential_sets', credentialSetIndex, 'options', optionIndex, index],
          message: `Credential set ${credentialSetIndex} refers to the credential query id '${id}', which is not in credentials`,
        })
      })
    })
  })
}

/**
 * The Digital Credentials Query Language (DCQL, pronounced [ˈdakl̩]) is a
 * JSON-encoded query language that allows the Verifier to request Verifiable
 * Presentations that match the query. The Verifier MAY encode constraints on the
 * combinations of credentials and claims that are requested. The Wallet evaluates
 * the query against the Verifiable Credentials it holds and returns Verifiable
 * Presentations matching the query.
 */
export namespace DcqlQuery {
  export const zModel = z
    .object({
      credentials: zNonEmptyArray(DcqlCredentialQuery.zModel).describe(
        'REQUIRED. A non-empty array of Credential Queries that specify the requested Verifiable Credentials.'
      ),
      credential_sets: zNonEmptyArray(CredentialSetQuery.zModel)
        .optional()
        .describe(
          'OPTIONAL. A non-empty array of credential set queries that specifies additional constraints on which of the requested Verifiable Credentials to return.'
        ),
    })
    .superRefine(checkCredentialQueryIds)
  export type Input = z.input<typeof zModel>
  export type Output = z.output<typeof zModel>
  /**
   * @deprecated `parse` checks that the credential query ids are unique and that the credential sets
   * only refer to them, and that the claim sets only refer to claims of their credential query.
   * @throws {DcqlParseError} with the `issues` of the query
   */
  export const validate = (dcqlQuery: Output) => {
    parse(dcqlQuery)
  }
  export const query = (dcqlQuery: Output, credentials: DcqlCredential[]) => {
    return runDcqlQuery(dcqlQuery, { credentials, presentation: false })
  }

  /**
   * Parse a DCQL query
   *
   * @throws {DcqlParseError} with the `issues` of the input when it is not a DCQL query
   */
  export const parse = (input: Input): Output => {
    return parseWithIssues(zModel, input, 'DCQL query')
  }
}
export type DcqlQuery = DcqlQuery.Output
