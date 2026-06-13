/**
 * SchemaMeta SDK Types
 *
 * Based on TS11 specification for the EUDI Catalogue of Attestations.
 * Types are derived from Zod schemas in schemas.ts.
 *
 * @see https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts11-interfaces-and-formats-for-catalogue-of-attributes-and-catalogue-of-schemes.md
 */

import type { Signer } from '@owf/crypto'
import type { Verifier } from '@owf/identity-common'
import type { z } from 'zod'
import type {
  AttestationFormatSchema,
  AttestationLoSSchema,
  BindingTypeSchema,
  FrameworkTypeSchema,
  GenericMetaSchema,
  MsoMdocMetaSchema,
  SchemaMetaSchema,
  SchemaURISchema,
  SdJwtMetaSchema,
  TrustAuthoritySchema,
} from './schemas'

// ============================================================================
// Enum Types
// ============================================================================

export type AttestationFormat = z.infer<typeof AttestationFormatSchema>
export type AttestationLoS = z.infer<typeof AttestationLoSSchema>
export type BindingType = z.infer<typeof BindingTypeSchema>
export type FrameworkType = z.infer<typeof FrameworkTypeSchema>

// ============================================================================
// Data Model Types
// ============================================================================

export type TrustAuthority = z.infer<typeof TrustAuthoritySchema>
export type SdJwtMeta = z.infer<typeof SdJwtMetaSchema>
export type MsoMdocMeta = z.infer<typeof MsoMdocMetaSchema>
export type GenericMeta = z.infer<typeof GenericMetaSchema>
export type SchemaURIMeta = SdJwtMeta | MsoMdocMeta | GenericMeta
export type SchemaURI = z.infer<typeof SchemaURISchema>
export type SchemaMeta = z.infer<typeof SchemaMetaSchema>

// ============================================================================
// Signed SchemaMeta Types
// ============================================================================

export interface SignOptions {
  schemaMeta: SchemaMeta
  keyId: string
  algorithm?: 'ES256' | 'ES384' | 'ES512' | 'RS256' | 'RS384' | 'RS512'
  certificates: string[]
  signer: Signer
}

export interface SignedSchemaMeta {
  jws: string
  header: {
    alg: string
    typ: string
    kid: string
    x5c: string[]
  }
  payload: SchemaMeta
  iat: number
}

// ============================================================================
// Verify Types
// ============================================================================

export interface VerifyOptions {
  jws: string
  verifier: Verifier
}

export interface VerifiedSchemaMeta {
  header: {
    alg: string
    typ: string
    kid: string
    x5c: string[]
  }
  payload: SchemaMeta
  iat: number
}

// ============================================================================
// Resolver and DCQL Types
// ============================================================================

export interface ResolvedSchemaReference {
  format: AttestationFormat
  uri: string
  integrity?: string
  meta?: SchemaURIMeta
  rawSchema: unknown
  parsedSchema?: Record<string, unknown>
}

export interface ResolveSchemaReferencesOptions {
  schemaMeta: SchemaMeta
  selectedFormats?: AttestationFormat[]
  resolve: (uri: string) => Promise<{ content: string | object; contentType?: string }>
  verifyIntegrity?: boolean
}

export interface DcqlTrustedAuthority {
  type: 'aki' | 'etsi_tl'
  values: string[]
}

export interface BuildDcqlFromSchemaMetaOptions {
  schemaMeta: SchemaMeta
  selectedFormats: AttestationFormat[]
  resolvedReferences?: ResolvedSchemaReference[]
  includeTrustedAuthorities?: boolean
  idPrefix?: string
}

export interface BuildDcqlFromSchemaMetaResult {
  credentials: Array<Record<string, unknown>>
}
