import { runCredentialQuery } from '../dcql-parser/dcql-credential-query-result.js'
import { matchCredentialSets } from '../dcql-query/m-dcql-credential-set-query.js'
import type { DcqlQuery } from '../dcql-query/m-dcql-query.js'
import type { DcqlCredential } from '../u-dcql-credential.js'
import type { DcqlQueryResult } from './m-dcql-query-result.js'

export const runDcqlQuery = (
  dcqlQuery: DcqlQuery.Output,
  ctx: {
    credentials: DcqlCredential[]
    presentation: boolean
  }
): DcqlQueryResult => {
  const credentialQueriesResults = Object.fromEntries(
    dcqlQuery.credentials.map((credentialQuery) => [credentialQuery.id, runCredentialQuery(credentialQuery, ctx)])
  )

  const { credentialSets, isSatisfied } = matchCredentialSets(
    dcqlQuery,
    (credentialQueryId) => credentialQueriesResults[credentialQueryId].success
  )

  return {
    ...dcqlQuery,
    can_be_satisfied: isSatisfied,
    credential_matches: credentialQueriesResults,
    credential_sets: credentialSets,
  }
}
