/**
 * LoTE SDK Types
 *
 * Based on ETSI TS 119 602 (LoTE - List of Trusted Entities) format.
 * Document types are derived from Zod schemas in schemas.ts.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf
 */

import type { Signer } from '@owf/crypto'
import type { z } from 'zod'
import type {
  CompatLoTEDocumentSchema,
  JWKPublicKeySchema,
  ListAndSchemeInformationSchema,
  LocalizedStringSchema,
  LocalizedURISchema,
  LoTEDocumentSchema,
  LoTEQualifierSchema,
  LoTESchema,
  OtherLoTEPointerSchema,
  PkiObjectSchema,
  PolicyOrLegalNoticeSchema,
  PostalAddressSchema,
  SchemeOperatorAddressSchema,
  ServiceDigitalIdentitySchema,
  ServiceHistoryInstanceSchema,
  ServiceInformationSchema,
  ServiceSupplyPointSchema,
  TrustedEntityAddressSchema,
  TrustedEntityInformationSchema,
  TrustedEntitySchema,
  TrustedEntityServiceSchema,
  X509CertificateRefSchema,
} from './schemas'

// ============================================================================
// Localized Value Types
// ============================================================================

export type LocalizedString = z.infer<typeof LocalizedStringSchema>
export type LocalizedURI = z.infer<typeof LocalizedURISchema>

// ============================================================================
// Address Types
// ============================================================================

export type PostalAddress = z.infer<typeof PostalAddressSchema>
export type SchemeOperatorAddress = z.infer<typeof SchemeOperatorAddressSchema>
export type TrustedEntityAddress = z.infer<typeof TrustedEntityAddressSchema>

// ============================================================================
// Digital Identity Types
// ============================================================================

export type PkiObject = z.infer<typeof PkiObjectSchema>
export type X509CertificateRef = z.infer<typeof X509CertificateRefSchema>
export type JWKPublicKey = z.infer<typeof JWKPublicKeySchema>
export type ServiceDigitalIdentity = z.infer<typeof ServiceDigitalIdentitySchema>

// ============================================================================
// Service Types
// ============================================================================

export type ServiceSupplyPoint = z.infer<typeof ServiceSupplyPointSchema>
export type ServiceInformationExtensions = unknown[]
export type ServiceInformation = z.infer<typeof ServiceInformationSchema>
export type ServiceHistoryInstance = z.infer<typeof ServiceHistoryInstanceSchema>
export type ServiceHistory = ServiceHistoryInstance[]
export type TrustedEntityService = z.infer<typeof TrustedEntityServiceSchema>

// ============================================================================
// Trusted Entity Types
// ============================================================================

export type TEInformationExtensions = unknown[]
export type TrustedEntityInformation = z.infer<typeof TrustedEntityInformationSchema>
export type TrustedEntity = z.infer<typeof TrustedEntitySchema>

// ============================================================================
// List and Scheme Information
// ============================================================================

export type PolicyOrLegalNotice = z.infer<typeof PolicyOrLegalNoticeSchema>
export type LoTEQualifier = z.infer<typeof LoTEQualifierSchema>
export type OtherLoTEPointer = z.infer<typeof OtherLoTEPointerSchema>
export type PointersToOtherLoTE = OtherLoTEPointer[]
export type SchemeExtensions = unknown[]
export type ListAndSchemeInformation = z.infer<typeof ListAndSchemeInformationSchema>

// ============================================================================
// LoTE Root Types
// ============================================================================

export type LoTE = z.infer<typeof LoTESchema>
export type LoTEDocument = z.infer<typeof LoTEDocumentSchema>
/** A LoTE document that `validateLoTE` accepts in compat mode */
export type CompatLoTEDocument = z.infer<typeof CompatLoTEDocumentSchema>

// ============================================================================
// Signed LoTE Types
// ============================================================================

/** Signed LoTE document (JWS format) */
export interface SignedLoTE {
  /** The compact JWS string */
  jws: string
  /** Decoded header */
  header: {
    alg: string
    typ: string
    kid?: string
    x5c?: string[]
  }
  /** Decoded payload */
  payload: LoTEDocument
}

/** Options for signing a LoTE document */
export interface SignOptions {
  /** The LoTE document to sign */
  lote: LoTEDocument
  /** Key ID for the signing key */
  keyId: string
  /** Algorithm (default: ES256) */
  algorithm?: 'ES256' | 'ES384' | 'ES512' | 'RS256' | 'RS384' | 'RS512'
  /** PEM-encoded certificates for x5c header (each element is a single PEM certificate) */
  certificates?: string[]
  /** Signer function for signing the JWS */
  signer: Signer
}
