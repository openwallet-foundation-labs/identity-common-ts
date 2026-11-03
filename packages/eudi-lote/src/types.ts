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
  zCompatLoTEDocument,
  zJWKPublicKey,
  zListAndSchemeInformation,
  zLocalizedString,
  zLocalizedURI,
  zLoTE,
  zLoTEDocument,
  zLoTEQualifier,
  zOtherLoTEPointer,
  zPkiObject,
  zPolicyOrLegalNotice,
  zPostalAddress,
  zSchemeOperatorAddress,
  zServiceDigitalIdentity,
  zServiceHistoryInstance,
  zServiceInformation,
  zServiceSupplyPoint,
  zTrustedEntity,
  zTrustedEntityAddress,
  zTrustedEntityInformation,
  zTrustedEntityService,
  zX509CertificateRef,
} from './schemas'

// ============================================================================
// Localized Value Types
// ============================================================================

export type LocalizedString = z.infer<typeof zLocalizedString>
export type LocalizedURI = z.infer<typeof zLocalizedURI>

// ============================================================================
// Address Types
// ============================================================================

export type PostalAddress = z.infer<typeof zPostalAddress>
export type SchemeOperatorAddress = z.infer<typeof zSchemeOperatorAddress>
export type TrustedEntityAddress = z.infer<typeof zTrustedEntityAddress>

// ============================================================================
// Digital Identity Types
// ============================================================================

export type PkiObject = z.infer<typeof zPkiObject>
export type X509CertificateRef = z.infer<typeof zX509CertificateRef>
export type JWKPublicKey = z.infer<typeof zJWKPublicKey>
export type ServiceDigitalIdentity = z.infer<typeof zServiceDigitalIdentity>

// ============================================================================
// Service Types
// ============================================================================

export type ServiceSupplyPoint = z.infer<typeof zServiceSupplyPoint>
export type ServiceInformationExtensions = unknown[]
export type ServiceInformation = z.infer<typeof zServiceInformation>
export type ServiceHistoryInstance = z.infer<typeof zServiceHistoryInstance>
export type ServiceHistory = ServiceHistoryInstance[]
export type TrustedEntityService = z.infer<typeof zTrustedEntityService>

// ============================================================================
// Trusted Entity Types
// ============================================================================

export type TEInformationExtensions = unknown[]
export type TrustedEntityInformation = z.infer<typeof zTrustedEntityInformation>
export type TrustedEntity = z.infer<typeof zTrustedEntity>

// ============================================================================
// List and Scheme Information
// ============================================================================

export type PolicyOrLegalNotice = z.infer<typeof zPolicyOrLegalNotice>
export type LoTEQualifier = z.infer<typeof zLoTEQualifier>
export type OtherLoTEPointer = z.infer<typeof zOtherLoTEPointer>
export type PointersToOtherLoTE = OtherLoTEPointer[]
export type SchemeExtensions = unknown[]
export type ListAndSchemeInformation = z.infer<typeof zListAndSchemeInformation>

// ============================================================================
// LoTE Root Types
// ============================================================================

export type LoTE = z.infer<typeof zLoTE>
export type LoTEDocument = z.infer<typeof zLoTEDocument>
/** A LoTE document that `validateLoTE` accepts in compat mode */
export type CompatLoTEDocument = z.infer<typeof zCompatLoTEDocument>

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
