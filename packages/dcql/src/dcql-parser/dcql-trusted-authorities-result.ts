import type { z } from 'zod'
import type { DcqlCredentialQuery } from '../dcql-query/m-dcql-credential-query.js'
import { getTrustedAuthorityParser } from '../dcql-query/m-dcql-trusted-authorities.js'

import type { DcqlTrustedAuthoritiesResult } from '../dcql-query-result/m-trusted-authorities-result.js'
import { asNonEmptyArrayOrUndefined, parseDcql, type ToNonEmptyArray } from '../u-dcql.js'
import type { DcqlCredential } from '../u-dcql-credential.js'

/** The parser of each trusted authority of the credential query, which is the same for every credential */
export const getTrustedAuthoritiesParsers = (credentialQuery: DcqlCredentialQuery) =>
  credentialQuery.trusted_authorities?.map(getTrustedAuthorityParser)

export const runTrustedAuthoritiesQuery = (
  credentialQuery: DcqlCredentialQuery,
  credential: DcqlCredential,
  parsers = getTrustedAuthoritiesParsers(credentialQuery)
): DcqlTrustedAuthoritiesResult => {
  if (!credentialQuery.trusted_authorities) {
    return {
      success: true,
    }
  }

  const failedTrustedAuthorities: z.output<typeof DcqlTrustedAuthoritiesResult.zTrustedAuthorityEntryFailureResult>[] =
    []

  for (const trustedAuthorityIndex of credentialQuery.trusted_authorities.keys()) {
    const parseResult = parseDcql(
      parsers?.[trustedAuthorityIndex] as ReturnType<typeof getTrustedAuthorityParser>,
      credential.authority
    )

    if (parseResult.success) {
      return {
        success: true,
        valid_trusted_authority: {
          success: true,
          trusted_authority_index: trustedAuthorityIndex,
          output: parseResult.data,
        },
        failed_trusted_authorities: asNonEmptyArrayOrUndefined(failedTrustedAuthorities),
      }
    }

    failedTrustedAuthorities.push({
      success: false,
      trusted_authority_index: trustedAuthorityIndex,
      issues: parseResult.issues,
    })
  }

  return {
    success: false,
    failed_trusted_authorities: failedTrustedAuthorities as ToNonEmptyArray<typeof failedTrustedAuthorities>,
  }
}
