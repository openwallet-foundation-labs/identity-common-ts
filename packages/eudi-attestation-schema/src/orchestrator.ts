import { buildDcqlFromSchemaMeta } from './dcql'
import { resolveSchemaReferences } from './resolver'
import type {
  AttestationFormat,
  BuildDcqlFromSchemaMetaResult,
  ResolvedSchemaReference,
  ResolveSchemaReferencesOptions,
  VerifiedSchemaMeta,
  VerifyOptions,
} from './types'
import { verifySchemaMeta } from './verifier'

export async function verifyResolveAndBuildDcql(options: {
  jws: string
  verifier: VerifyOptions['verifier']
  selectedFormats: AttestationFormat[]
  resolve: ResolveSchemaReferencesOptions['resolve']
  verifyIntegrity?: boolean
  includeTrustedAuthorities?: boolean
  idPrefix?: string
}): Promise<{
  verified: VerifiedSchemaMeta
  resolvedReferences: ResolvedSchemaReference[]
  dcql: BuildDcqlFromSchemaMetaResult
}> {
  const { jws, verifier, selectedFormats, resolve, verifyIntegrity, includeTrustedAuthorities, idPrefix } = options

  const verified = await verifySchemaMeta({ jws, verifier })

  const resolvedReferences = await resolveSchemaReferences({
    schemaMeta: verified.payload,
    selectedFormats,
    resolve,
    verifyIntegrity,
  })

  const dcql = buildDcqlFromSchemaMeta({
    schemaMeta: verified.payload,
    selectedFormats,
    resolvedReferences,
    includeTrustedAuthorities,
    idPrefix,
  })

  return {
    verified,
    resolvedReferences,
    dcql,
  }
}
