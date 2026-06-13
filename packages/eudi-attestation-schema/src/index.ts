// Builders
export {
  SchemaMetaBuilder,
  SchemaURIBuilder,
  schemaMeta,
  schemaURI,
  TrustAuthorityBuilder,
  trustAuthority,
} from './builders'
// DCQL
export { buildDcqlFromSchemaMeta, toDcqlCredentialInput, toDcqlTrustedAuthorities } from './dcql'
// Orchestrator
export { verifyResolveAndBuildDcql } from './orchestrator'
// Resolver
export { resolveSchemaReferences } from './resolver'
// Exception
export { SchemaMetaException } from './schema-meta-exception'
// Schemas
export {
  AttestationFormatSchema,
  AttestationFormatValues,
  AttestationLoSSchema,
  AttestationLoSValues,
  BindingTypeSchema,
  BindingTypeValues,
  FrameworkTypeSchema,
  FrameworkTypeValues,
  GenericMetaSchema,
  MsoMdocMetaSchema,
  SchemaMetaSchema,
  SchemaURISchema,
  SdJwtMetaSchema,
  TrustAuthoritySchema,
} from './schemas'
// Signer
export { signSchemaMeta } from './signer'

// Types
export type {
  AttestationFormat,
  AttestationLoS,
  BindingType,
  BuildDcqlFromSchemaMetaOptions,
  BuildDcqlFromSchemaMetaResult,
  DcqlTrustedAuthority,
  FrameworkType,
  GenericMeta,
  MsoMdocMeta,
  ResolvedSchemaReference,
  ResolveSchemaReferencesOptions,
  SchemaMeta,
  SchemaURI,
  SchemaURIMeta,
  SdJwtMeta,
  SignedSchemaMeta,
  SignOptions,
  TrustAuthority,
  VerifiedSchemaMeta,
  VerifyOptions,
} from './types'
// Validator
export type { ValidationError, ValidationResult } from './validator'
export { assertValidSchemaMeta, validateSchemaMeta } from './validator'
// Verifier
export { verifySchemaMeta } from './verifier'
