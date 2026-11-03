import type { z } from 'zod'
import type { DcqlCredentialQuery } from '../dcql-query/m-dcql-credential-query.js'
import { getTrustedAuthorityParser } from '../dcql-query/m-dcql-trusted-authorities.js'

import type { DcqlTrustedAuthoritiesResult } from '../dcql-query-result/m-trusted-authorities-result.js'
import { asNonEmptyArrayOrUndefined, parseDcql, type ToNonEmptyArray } from '../u-dcql.js'
import type { DcqlCredential } from '../u-dcql-credential.js'

export const runTrustedAuthoritiesQuery = (
  credentialQuery: DcqlCredentialQuery,
  credential: DcqlCredential
): DcqlTrustedAuthoritiesResult => {
  if (!credentialQuery.trusted_authorities) {
    return {
      success: true,
    }
  }

  const failedTrustedAuthorities: z.output<typeof DcqlTrustedAuthoritiesResult.zTrustedAuthorityEntryFailureResult>[] =
    []

  for (const [trustedAuthorityIndex, trustedAuthority] of credentialQuery.trusted_authorities.entries()) {
    const trustedAuthorityParser = getTrustedAuthorityParser(trustedAuthority)
    const parseResult = parseDcql(trustedAuthorityParser, credential.authority)

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
