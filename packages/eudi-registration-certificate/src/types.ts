/**
 * Registration Certificate SDK Types
 *
 * Based on ETSI TS 119 475 (Wallet-Relying Party Registration Certificates).
 * Document types are derived from Zod schemas in schemas.ts.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import type { CoseKey, Sign1Context, SignatureAlgorithm } from '@owf/cose'
import type { FetchCallback, FetchLimits, OrPromise } from '@owf/identity-common'
import type { SignJwsCallback, VerifyJwsCallback } from '@owf/jose'
import type { z } from 'zod'
import type { RegistrationCertificateCwtPayload } from './cwt'
import type { RegistrationCertificateDialect } from './dialect'
import type {
  zClaim,
  zCredential,
  zIntermediary,
  zLegalPersonSubject,
  zMultiLangString,
  zNaturalPersonSubject,
  zProvidedAttestation,
  zRegistrationCertificateCwt,
  zRegistrationCertificateCwtHeader,
  zRegistrationCertificateJwt,
  zRegistrationCertificateJwtHeader,
  zRegistrationCertificatePayload,
  zStatus,
  zStatusList,
  zSupervisoryAuthority,
} from './schemas'

// ============================================================================
// Multilingual Types
// ============================================================================

/** Multilingual string with language tag (B.2.6 Class MultiLangString) */
export type MultiLangString = z.infer<typeof zMultiLangString>

// ============================================================================
// Identity Types
// ============================================================================

/** Supervisory Authority (Data Protection Authority) */
export type SupervisoryAuthority = z.infer<typeof zSupervisoryAuthority>

/** Claim specification for credential attributes (B.2.10 Class Claim) */
export type Claim = z.infer<typeof zClaim>

/** Credential specification for attestations (B.2.9 Class Credential) */
export type Credential = z.infer<typeof zCredential>

/** Credential issued by the WRP for `provides_attestations` (Table 8) */
export type ProvidedAttestation = z.infer<typeof zProvidedAttestation>

/** Status list reference for certificate validity */
export type StatusList = z.infer<typeof zStatusList>

/** Status reference for registration certificate validity */
export type Status = z.infer<typeof zStatus>

/** Intermediary information */
export type Intermediary = z.infer<typeof zIntermediary>

// ============================================================================
// Registration Certificate Document Types
// ============================================================================

/** Registration Certificate Payload */
export type RegistrationCertificatePayload = z.infer<typeof zRegistrationCertificatePayload>

/** Legal person subject payload */
export type LegalPersonSubject = z.infer<typeof zLegalPersonSubject>

/** Natural person subject payload */
export type NaturalPersonSubject = z.infer<typeof zNaturalPersonSubject>

// ============================================================================
// Header Types
// ============================================================================

/** JWT Header for registration certificate */
export type RegistrationCertificateJwtHeader = z.infer<typeof zRegistrationCertificateJwtHeader>

/** CWT Header for registration certificate */
export type RegistrationCertificateCwtHeader = z.infer<typeof zRegistrationCertificateCwtHeader>

// ============================================================================
// Complete Registration Certificate Types
// ============================================================================

/** Complete JWT registration certificate document */
export type RegistrationCertificateJwt = z.infer<typeof zRegistrationCertificateJwt>

/** Complete CWT registration certificate document */
export type RegistrationCertificateCwt = z.infer<typeof zRegistrationCertificateCwt>

// ============================================================================
// Signed Registration Certificate Types
// ============================================================================

/** Signed JWT registration certificate (compact JWS format) */
export interface SignedRegistrationCertificateJwt {
  /** The compact JWS string */
  jws: string
  /** Decoded header */
  header: RegistrationCertificateJwtHeader
  /** Decoded payload */
  payload: RegistrationCertificatePayload
}

/** Signed CWT registration certificate (COSE_Sign1) */
export interface SignedRegistrationCertificateCwt {
  /** The encoded COSE_Sign1 */
  cwt: Uint8Array
  /** Decoded protected header */
  header: RegistrationCertificateCwtHeader
  /** Decoded payload */
  payload: RegistrationCertificatePayload
}

/** Options for signing a registration certificate as a JWT */
export interface SignJwtOptions {
  /** The registration certificate payload to sign */
  payload: RegistrationCertificatePayload
  /** Required subject of the access certificate the registration certificate is intended to authorize */
  accessCertificateSub: string
  /** Algorithm (default: ES256) */
  algorithm?: RegistrationCertificateJwtHeader['alg']
  /** PEM-encoded certificates for x5c header (each element is a single PEM certificate) */
  certificates: string[]
  /** Key ID (optional) */
  keyId?: string
  /** JAdES claimed signing time; defaults to now */
  signingTime?: number | string | Date
  /** Wire dialect to emit; defaults to ETSI TS 119 475 v1.2.1 as published */
  dialect?: RegistrationCertificateDialect
  /** Signs the JWS with the key of the first certificate, see `@owf/jose` */
  signJwsCallback: SignJwsCallback
}

/** Options for signing a registration certificate as a CWT */
export interface SignCwtOptions extends Pick<SignJwtOptions, 'accessCertificateSub' | 'certificates'> {
  /**
   * The payload: a registration certificate payload, or its CBOR claims set, to extend or modify it before it is signed
   */
  payload: RegistrationCertificatePayload | RegistrationCertificateCwtPayload
  /** Wire dialect of a registration certificate payload; defaults to ETSI TS 119 475 v1.2.1 as published */
  dialect?: RegistrationCertificateDialect
  /** The key to sign with */
  signingKey: CoseKey
  /** Signature algorithm; defaults to the algorithm of `signingKey` */
  algorithm?: SignatureAlgorithm
  /** Signs the COSE_Sign1 with `signingKey`, see `@owf/cose` */
  signCoseCallback: Sign1Context['sign']
}

// ============================================================================
// Verification Types
// ============================================================================

/**
 * Verifies the signature of a COSE_Sign1 with the key of the first certificate of `x5chain`, and decides whether the
 * chain is trusted. Returning `false` and throwing both fail.
 */
export type VerifyCoseCallback = (options: {
  /** The DER encoded certificates of the protected `x5chain` header (RFC 9360), leaf first */
  x5chain: Uint8Array[]
  /** The signature algorithm of the protected `alg` header */
  algorithm: SignatureAlgorithm
  /** The `Sig_structure` the signature is over (RFC 9052 section 4.4) */
  toBeVerified: Uint8Array
  signature: Uint8Array
}) => OrPromise<boolean>

/** The callbacks of registration certificate verification */
export interface VerifyRegistrationCertificateCallbacks {
  /**
   * Verifies the signature of a JWT, a registration certificate or a status list, and decides whether its signer is
   * trusted (see `@owf/jose`)
   */
  verifyJws: VerifyJwsCallback
  /** The same for a CWT */
  verifyCose: VerifyCoseCallback
  /** Fetches the status list, with `{ type: 'statusList' }` as its third argument; defaults to the global `fetch` */
  fetch?: FetchCallback<'statusList'>
  /** The maximum size of the status list response; 16 MiB by default (see `FetchLimits` of `@owf/identity-common`) */
  fetchLimits?: FetchLimits<'statusList'>
}

// ============================================================================
// Builder Input Types
// ============================================================================

/** Input for creating a legal person registration certificate */
export interface LegalPersonRegistrationCertificateInput {
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

/** Input for creating a natural person registration certificate */
export interface NaturalPersonRegistrationCertificateInput {
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
