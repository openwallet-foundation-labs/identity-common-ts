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
import type { TypeMetadataFormat } from '@sd-jwt/sd-jwt-vc'
import type { z } from 'zod'
import type {
  zAttestationFormat,
  zAttestationLos,
  zBindingType,
  zFrameworkType,
  zIssuanceProfile,
  zMsoMdocMeta,
  zOid4vciClaim,
  zOid4vciClaimDisplay,
  zOid4vciCredentialMetadata,
  zOid4vciDisplay,
  zProofType,
  zSchemaMeta,
  zSchemaUri,
  zSdJwtMeta,
  zSdJwtVcTypeMetadata,
  zStatusMechanism,
  zTrustAuthority,
} from './schemas'

// ============================================================================
// Enum Types
// ============================================================================

export type AttestationFormat = z.infer<typeof zAttestationFormat>
export type AttestationLos = z.infer<typeof zAttestationLos>
export type BindingType = z.infer<typeof zBindingType>
export type FrameworkType = z.infer<typeof zFrameworkType>

// ============================================================================
// Data Model Types
// ============================================================================

export type TrustAuthority = z.infer<typeof zTrustAuthority>
export type SdJwtMeta = z.infer<typeof zSdJwtMeta>
export type MsoMdocMeta = z.infer<typeof zMsoMdocMeta>
export type Oid4vciCredentialMetadata = z.infer<typeof zOid4vciCredentialMetadata>
export type Oid4vciDisplay = z.infer<typeof zOid4vciDisplay>
export type Oid4vciClaimDisplay = z.infer<typeof zOid4vciClaimDisplay>
export type Oid4vciClaim = z.infer<typeof zOid4vciClaim>
export type SdJwtVcTypeMetadata = z.infer<typeof zSdJwtVcTypeMetadata>
export type SchemaUriMeta = SdJwtMeta | MsoMdocMeta
export type SchemaUri = z.infer<typeof zSchemaUri>
export type ProofType = z.infer<typeof zProofType>
export type StatusMechanism = z.infer<typeof zStatusMechanism>
export type IssuanceProfile = z.infer<typeof zIssuanceProfile>
export type SchemaMeta = z.infer<typeof zSchemaMeta>

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
  integrity: string
  meta?: SchemaUriMeta
  rawSchema: unknown
  /** Present for `dc+sd-jwt` references that resolve to Type Metadata, merged over `extends`. */
  typeMetadata?: TypeMetadataFormat
  /** The document when the reference is a plain JSON Schema. */
  parsedSchema?: Record<string, unknown>
}

/** Integrity can only be verified over `string` or `Uint8Array`, never over parsed content. */
export type ResolverContent = string | Uint8Array | object

export interface ResolveSchemaReferencesOptions {
  schemaMeta: SchemaMeta
  selectedFormats?: AttestationFormat[]
  resolve: (uri: string) => Promise<{ content: ResolverContent; contentType?: string }>
  /** Defaults to `true`. */
  verifyIntegrity?: boolean
  /** Defaults to 10. */
  maxExtendsDepth?: number
}

export interface DcqlTrustedAuthority {
  type: 'etsi_tl'
  values: string[]
}

export type DcqlClaimsPathComponent = string | number | null

export type DcqlClaimsPath = [DcqlClaimsPathComponent, ...DcqlClaimsPathComponent[]]

export interface DcqlClaim {
  path: DcqlClaimsPath
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

// ============================================================================
// OID4VCI Issuer Metadata Mapping Types
// ============================================================================

export interface BuildCredentialConfigurationTemplateOptions {
  schemaMeta: SchemaMeta
  format: AttestationFormat
  resolvedReferences?: ResolvedSchemaReference[]
  credentialConfigurationId?: string
}

export interface CredentialConfigurationTemplate {
  credentialConfigurationId: string
  credentialConfiguration: Record<string, unknown>
  /** Members no catalogue entry can supply, listed so an issuer knows what is left to fill in. */
  deploymentFields: {
    credentialConfiguration: string[]
    issuerMetadata: string[]
  }
}

export interface ValidateIssuerMetadataOptions {
  issuerMetadata: unknown
  schemaMeta: SchemaMeta
  format: AttestationFormat
  credentialConfigurationId?: string
}
