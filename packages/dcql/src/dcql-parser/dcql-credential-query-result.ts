import type { DcqlCredentialQuery } from '../dcql-query/m-dcql-credential-query.js'
import type { DcqlQueryResult } from '../dcql-query-result/m-dcql-query-result.js'
import { asNonEmptyArrayOrUndefined, isNonEmptyArray } from '../u-dcql.js'
import type { DcqlCredential } from '../u-dcql-credential.js'
import { getClaimsParsers, runClaimsQuery } from './dcql-claims-query-result.js'
import { getMetaParser, runMetaQuery } from './dcql-meta-query-result.js'
import { getTrustedAuthoritiesParsers, runTrustedAuthoritiesQuery } from './dcql-trusted-authorities-result.js'

export const runCredentialQuery = (
  credentialQuery: DcqlCredentialQuery,
  ctx: {
    credentials: DcqlCredential[]
    presentation: boolean
  }
): DcqlQueryResult.CredentialQueryItemResult => {
  const { credentials, presentation } = ctx

  const validCredentials: DcqlQueryResult.CredentialQueryItemCredentialSuccessResult[] = []
  const failedCredentials: DcqlQueryResult.CredentialQueryItemCredentialFailureResult[] = []

  // The parsers only depend on the credential query. They are built on the first credential, so a query
  // without credentials does not throw for a format that is not supported.
  let trustedAuthoritiesParsers: ReturnType<typeof getTrustedAuthoritiesParsers>
  let claimsParsers: ReturnType<typeof getClaimsParsers>
  let metaParser: ReturnType<typeof getMetaParser> | undefined

  for (const [credentialIndex, credential] of credentials.entries()) {
    trustedAuthoritiesParsers ??= getTrustedAuthoritiesParsers(credentialQuery)
    const trustedAuthorityResult = runTrustedAuthoritiesQuery(credentialQuery, credential, trustedAuthoritiesParsers)
    claimsParsers ??= getClaimsParsers(credentialQuery, presentation)
    const claimsResult = runClaimsQuery(credentialQuery, { credential, presentation, parsers: claimsParsers })
    metaParser ??= getMetaParser(credentialQuery)
    const metaResult = runMetaQuery(credentialQuery, credential, metaParser)

    // if we found a valid claim set and trusted authority, the credential succeeded processing
    if (claimsResult.success && trustedAuthorityResult.success && metaResult.success) {
      validCredentials.push({
        success: true,

        input_credential_index: credentialIndex,
        trusted_authorities: trustedAuthorityResult,
        meta: metaResult,
        claims: claimsResult,
      })
    } else {
      failedCredentials.push({
        success: false,
        input_credential_index: credentialIndex,
        trusted_authorities: trustedAuthorityResult,
        meta: metaResult,
        claims: claimsResult,
      })
    }
  }

  if (isNonEmptyArray(validCredentials)) {
    return {
      success: true,
      credential_query_id: credentialQuery.id,
      failed_credentials: asNonEmptyArrayOrUndefined(failedCredentials),
      valid_credentials: validCredentials,
    }
  }

  return {
    success: false,
    credential_query_id: credentialQuery.id,
    // Can be undefined if no credentials were provided to the query
    failed_credentials: asNonEmptyArrayOrUndefined(failedCredentials),
    valid_credentials: undefined,
  }
}
