/**
 * WRPRC SDK Types
 *
 * Based on ETSI TS 119 475 (Wallet-Relying Party Registration Certificates).
 * Document types are derived from Zod schemas in schemas.ts.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import type { Signer } from '@owf/crypto'
import type { z } from 'zod'
import type { WRPRCDialect } from './dialect'
import type {
  ActSchema,
  ClaimSchema,
  CredentialSchema,
  IntermediarySchema,
  LegalPersonSubjectSchema,
  MultiLangStringSchema,
  NaturalPersonSubjectSchema,
  StatusListSchema,
  StatusSchema,
  SupervisoryAuthoritySchema,
  WRPRCCWTHeaderSchema,
  WRPRCCWTSchema,
  WRPRCJWTHeaderSchema,
  WRPRCJWTSchema,
  WRPRCPayloadSchema,
} from './schemas'

// ============================================================================
// Multilingual Types
// ============================================================================

/** Multilingual string with language tag (B.2.6 Class MultiLangString) */
export type MultiLangString = z.infer<typeof MultiLangStringSchema>

// ============================================================================
// Identity Types
// ============================================================================

/** Supervisory Authority (Data Protection Authority) */
export type SupervisoryAuthority = z.infer<typeof SupervisoryAuthoritySchema>

/** Claim specification for credential attributes (B.2.10 Class Claim) */
export type Claim = z.infer<typeof ClaimSchema>

/** Credential specification for attestations (B.2.9 Class Credential) */
export type Credential = z.infer<typeof CredentialSchema>

/** Status list reference for certificate validity */
export type StatusList = z.infer<typeof StatusListSchema>

/** Status reference for WRPRC validity */
export type Status = z.infer<typeof StatusSchema>

/** Intermediary information */
export type Intermediary = z.infer<typeof IntermediarySchema>

/** Actor claim under intermediation (Table 10) */
export type Act = z.infer<typeof ActSchema>

// ============================================================================
// WRPRC Document Types
// ============================================================================

/** WRPRC Payload */
export type WRPRCPayload = z.infer<typeof WRPRCPayloadSchema>

/** Legal person subject payload */
export type LegalPersonSubject = z.infer<typeof LegalPersonSubjectSchema>

/** Natural person subject payload */
export type NaturalPersonSubject = z.infer<typeof NaturalPersonSubjectSchema>

// ============================================================================
// Header Types
// ============================================================================

/** JWT Header for WRPRC */
export type WRPRCJWTHeader = z.infer<typeof WRPRCJWTHeaderSchema>

/** CWT Header for WRPRC */
export type WRPRCCWTHeader = z.infer<typeof WRPRCCWTHeaderSchema>

// ============================================================================
// Complete WRPRC Types
// ============================================================================

/** Complete JWT WRPRC document */
export type WRPRCJWT = z.infer<typeof WRPRCJWTSchema>

/** Complete CWT WRPRC document */
export type WRPRCCWT = z.infer<typeof WRPRCCWTSchema>

// ============================================================================
// Signed WRPRC Types
// ============================================================================

/** Signed JWT WRPRC (compact JWS format) */
export interface SignedWRPRC {
  /** The compact JWS string */
  jws: string
  /** Decoded header */
  header: WRPRCJWTHeader
  /** Decoded payload */
  payload: WRPRCPayload
}

/** Options for signing a WRPRC */
export interface SignOptions {
  /** The WRPRC payload to sign */
  payload: WRPRCPayload
  /** Algorithm (default: ES256) */
  algorithm?: WRPRCJWTHeader['alg']
  /** PEM-encoded certificates for x5c header (each element is a single PEM certificate) */
  certificates: string[]
  /** Key ID (optional) */
  keyId?: string
  /** JAdES claimed signing time; defaults to now */
  signingTime?: number | string | Date
  /** Wire dialect to emit; defaults to ETSI TS 119 475 v1.2.1 as published */
  dialect?: WRPRCDialect
  /** Signer function for signing the JWS */
  signer: Signer
}

// ============================================================================
// Builder Input Types
// ============================================================================

/** Input for creating a legal person WRPRC */
export interface LegalPersonWRPRCInput {
  /** Trade name (for display) */
  name: string
  /** Legal name of the organization */
  legalName: string
  /** Semantic identifier (e.g., "LEIXG-529900T8BM49AURSDO55") */
  identifier: string
  /** Country code (ISO 3166-1 Alpha-2) */
  country: string
  /** URL to the national registry API endpoint */
  registryUri: string
  /** List of entitlement URIs */
  entitlements: string[]
}

/** Input for creating a natural person WRPRC */
export interface NaturalPersonWRPRCInput {
  /** Trade name (for display) */
  name: string
  /** Given name(s) */
  givenName: string
  /** Family name */
  familyName: string
  /** Semantic identifier (e.g., "TINIT-RSSMRA85T10A562S") */
  identifier: string
  /** Country code (ISO 3166-1 Alpha-2) */
  country: string
  /** URL to the national registry API endpoint */
  registryUri: string
  /** List of entitlement URIs */
  entitlements: string[]
}
