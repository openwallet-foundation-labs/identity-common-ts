import type { JsonWebKey, OrPromise } from '@owf/identity-common'
import type { KeyUsageType } from '@peculiar/asn1-x509'
import type { AttributeName, CrlReason, QcType, SignatureAlgorithm } from './constants'
import type { CertificateInput } from './encoding'
import type { NameAttributeInput } from './name'

export type { KeyUsageType }

// ============================================================================
// Common
// ============================================================================

/** A single attribute of a distinguished name */
export interface DistinguishedNameAttribute {
  /** Attribute type OID */
  type: string
  /** Well-known attribute name, when the OID is known */
  name?: AttributeName
  /** Attribute value as string (non-string values are `#` followed by the hex encoded DER) */
  value: string
}

/** A distinguished name with accessors for common attributes */
export interface DistinguishedName {
  /** All attributes in encoding order (multi-valued RDNs are flattened) */
  attributes: DistinguishedNameAttribute[]
  /** RFC 4514 string representation, most specific RDN first */
  rfc4514: string
  commonName?: string
  organizationName?: string
  organizationIdentifier?: string
  organizationalUnitNames: string[]
  countryName?: string
  localityName?: string
  stateOrProvinceName?: string
  serialNumber?: string
  givenName?: string
  surname?: string
  pseudonym?: string
}

export interface ParsedPublicKey {
  /** Key algorithm OID */
  algorithm: string
  /** Named curve OID for EC keys */
  namedCurve?: string
  /** DER encoded SubjectPublicKeyInfo */
  spki: Uint8Array
  /** JWK representation, for EC (P-256, P-384, P-521) and RSA keys */
  jwk?: JsonWebKey
}

export interface X509Extension {
  oid: string
  critical: boolean
  /** DER encoded extension value (content of extnValue) */
  value: Uint8Array
}

/** Result of a signature over a DER structure (certificate or CRL) */
interface SignedStructure {
  /** Signature algorithm OID */
  signatureAlgorithm: string
  /** Signature algorithm name, when supported by this package */
  signatureAlgorithmName?: SignatureAlgorithm
  /** The signature value as encoded in the structure (DER for ECDSA) */
  signature: Uint8Array
}

// ============================================================================
// Certificates
// ============================================================================

/** A certificate policy entry (RFC 5280 clause 4.2.1.4) */
export interface CertificatePolicyInformation {
  oid: string
  cpsUris: string[]
  /** Explicit text of any user notice qualifiers */
  userNotices: string[]
}

export interface OtherNameValue {
  typeId: string
  /** DER encoding of the value */
  value: Uint8Array
  /** The decoded value when it is an ASN.1 string type */
  text?: string
}

export interface SubjectAlternativeNames {
  dnsNames: string[]
  uris: string[]
  emails: string[]
  ipAddresses: string[]
  directoryNames: DistinguishedName[]
  otherNames: OtherNameValue[]
}

/** QCStatements (RFC 3739, ETSI EN 319 412-5) */
export interface QcStatements {
  /** All statement ids present, in order */
  statementIds: string[]
  /** id-etsi-qcs-QcCompliance present */
  qcCompliance: boolean
  /** id-etsi-qcs-QcSSCD present */
  qcSSCD: boolean
  /** Known QcType values; unknown type OIDs are returned as-is */
  qcTypes: (QcType | string)[]
  /** PKI disclosure statements */
  pds: { url: string; language: string }[]
  /** QcCClegislation country codes */
  legislationCountries: string[]
}

/** A parsed X.509 certificate */
export interface Certificate extends SignedStructure {
  /** DER encoding of the certificate */
  der: Uint8Array
  /** PEM encoding of the certificate */
  pem: string
  /** X.509 version (1, 2 or 3) */
  version: number
  /** Lowercase hex encoded serial number, as encoded (including a leading 00 octet if present) */
  serialNumber: string
  issuer: DistinguishedName
  subject: DistinguishedName
  notBefore: Date
  notAfter: Date
  publicKey: ParsedPublicKey
  /** DER encoded TBSCertificate, i.e. the signed bytes */
  tbsCertificate: Uint8Array

  policies: CertificatePolicyInformation[]
  subjectAlternativeNames: SubjectAlternativeNames
  keyUsage?: KeyUsageType[]
  extendedKeyUsage?: string[]
  basicConstraints?: { cA: boolean; pathLenConstraint?: number }
  /** Lowercase hex */
  subjectKeyIdentifier?: string
  /** Lowercase hex */
  authorityKeyIdentifier?: string
  /** URIs of the full names of all CRL distribution points */
  crlDistributionPoints: string[]
  ocspUrls: string[]
  caIssuersUrls: string[]
  qcStatements?: QcStatements

  extensions: X509Extension[]
}

// ============================================================================
// CRLs
// ============================================================================

export interface RevokedCertificate {
  /** Lowercase hex encoded serial number, as encoded */
  serialNumber: string
  revocationDate: Date
  /** Absent means unspecified */
  reason?: CrlReason
  invalidityDate?: Date
  /** Issuer of the revoked certificate for indirect CRLs (applies to this and following entries) */
  certificateIssuer?: DistinguishedName
  extensions: X509Extension[]
}

export interface IssuingDistributionPoint {
  /** URIs of the distribution point full name */
  distributionPointUris: string[]
  onlyContainsUserCerts: boolean
  onlyContainsCACerts: boolean
  onlyContainsAttributeCerts: boolean
  indirectCRL: boolean
  /** Reason flags when the CRL covers only some reasons */
  onlySomeReasons?: string[]
}

/** A parsed X.509 certificate revocation list (RFC 5280 clause 5) */
export interface Crl extends SignedStructure {
  der: Uint8Array
  pem: string
  /** CRL version (1 or 2) */
  version: number
  issuer: DistinguishedName
  thisUpdate: Date
  nextUpdate?: Date
  /** DER encoded TBSCertList, i.e. the signed bytes */
  tbsCertList: Uint8Array
  crlNumber?: bigint
  /** Set for delta CRLs: the CRL number of the base CRL */
  deltaCrlIndicator?: bigint
  /** Lowercase hex */
  authorityKeyIdentifier?: string
  issuingDistributionPoint?: IssuingDistributionPoint
  /** URIs of freshest CRL (delta CRL) distribution points */
  freshestCrl: string[]
  revokedCertificates: RevokedCertificate[]
  extensions: X509Extension[]
}

// ============================================================================
// Signing and verification callbacks
// ============================================================================

/**
 * Signs DER encoded to-be-signed bytes (TBSCertificate or TBSCertList) with the issuer key.
 *
 * The private key never has to be handed to this package: implement the callback with
 * WebCrypto, a KMS, an HSM or a remote signing service.
 */
export type TbsSigner = (tbs: Uint8Array) => OrPromise<Uint8Array>

/** Encoding of ECDSA signatures returned by a signer: `ieee-p1363` (r || s, WebCrypto) or `der` */
export type SignatureEncoding = 'ieee-p1363' | 'der'

/**
 * Hash function used to derive key identifiers. Receives the subject public key bytes and is
 * called with `sha-256`; the first 160 bits are used (RFC 7093 method 1). Compatible with
 * `digest` from `@owf/crypto`.
 */
export type KeyIdentifierHasher = (data: ArrayBuffer, alg: string) => OrPromise<Uint8Array>

export interface SignatureVerificationInput {
  /** DER encoded to-be-signed bytes */
  data: Uint8Array
  /** Signature as encoded in the structure (DER for ECDSA) */
  signature: Uint8Array
  /** Signature as r || s for ECDSA, as expected by WebCrypto; same as `signature` for RSA */
  signatureP1363: Uint8Array
  /** Signature algorithm OID */
  signatureAlgorithm: string
  signatureAlgorithmName?: SignatureAlgorithm
  /** Public key of the signer */
  publicKey: ParsedPublicKey
}

export type SignatureVerifier = (input: SignatureVerificationInput) => OrPromise<boolean>

// ============================================================================
// Certificate creation
// ============================================================================

export interface SubjectAlternativeNamesInput {
  dnsNames?: string[]
  uris?: string[]
  emails?: string[]
  /** otherName entries; use {@link stringOtherName} for string valued types */
  otherNames?: { typeId: string; value: Uint8Array }[]
}

export interface CertificateTemplate {
  /** Subject attributes in encoding order, most general first (e.g. C, O, CN) */
  subject: readonly NameAttributeInput[]
  /** Public key of the subject as DER SubjectPublicKeyInfo or public JWK (private JWKs are rejected) */
  subjectPublicKey: Uint8Array | JsonWebKey
  /**
   * Certificate of the issuing CA; supplies the issuer name, authority key identifier and
   * the key type for signature encoding. Omit for a self-signed certificate.
   */
  issuerCertificate?: CertificateInput
  /** Positive serial number as bytes or hex string (at most 20 octets) */
  serialNumber: Uint8Array | string
  notBefore: Date
  notAfter: Date
  /** Algorithm the issuer key signs with */
  signatureAlgorithm: SignatureAlgorithm
  /** Marked critical. Defaults to `{ cA: false }` */
  basicConstraints?: { cA: boolean; pathLenConstraint?: number }
  /** Marked critical. Defaults to `['digitalSignature']`, or `['keyCertSign', 'crlSign']` for CAs */
  keyUsage?: KeyUsageType[]
  extendedKeyUsage?: string[]
  certificatePolicies?: { oid: string; cpsUris?: string[] }[]
  subjectAlternativeNames?: SubjectAlternativeNamesInput
  crlDistributionPoints?: string[]
  ocspUrls?: string[]
  caIssuersUrls?: string[]
  /** QCStatements; QcCompliance is always included when set */
  qcStatements?: {
    qcTypes?: QcType[]
    qcSSCD?: boolean
    pds?: { url: string; language: string }[]
    legislationCountries?: string[]
  }
  /** Adds a subject key identifier (and the authority key identifier of self-signed certificates) */
  hasher?: KeyIdentifierHasher
  /** Additional extensions, appended as-is */
  extensions?: X509Extension[]
}

/** The to-be-signed bytes of a certificate or CRL, plus what is needed to assemble it */
export interface PreparedSignedStructure {
  tbs: Uint8Array
  signatureAlgorithm: SignatureAlgorithm
  /** Public key of the signer, used to encode ECDSA signatures */
  signerPublicKey: ParsedPublicKey
}

export interface SignOptions {
  signer: TbsSigner
  /** Encoding of ECDSA signatures returned by the signer; defaults to `ieee-p1363` (WebCrypto) */
  signatureEncoding?: SignatureEncoding
}

// ============================================================================
// CRL creation and revocation checking
// ============================================================================

export interface CrlTemplate {
  /** Certificate of the CRL issuer */
  issuerCertificate: CertificateInput
  thisUpdate: Date
  nextUpdate: Date
  /** Monotonically increasing CRL number (RFC 5280 clause 5.2.3) */
  crlNumber: bigint | number
  signatureAlgorithm: SignatureAlgorithm
  revokedCertificates?: {
    serialNumber: Uint8Array | string
    revocationDate: Date
    reason?: CrlReason
    invalidityDate?: Date
  }[]
  /** Scope of the CRL; marked critical */
  issuingDistributionPoint?: {
    distributionPointUris?: string[]
    onlyContainsUserCerts?: boolean
    onlyContainsCACerts?: boolean
  }
  /** Additional CRL extensions, appended as-is */
  extensions?: X509Extension[]
}

export type RevocationStatus =
  | { status: 'good' }
  | { status: 'revoked'; revocationDate: Date; reason?: CrlReason; invalidityDate?: Date }
  | { status: 'unknown'; reason: RevocationUnknownReason; message: string }

export type RevocationUnknownReason =
  | 'issuer_mismatch'
  | 'crl_not_yet_valid'
  | 'crl_expired'
  | 'out_of_scope'
  | 'delta_crl'
  | 'unsupported_critical_extension'
  | 'invalid_signature'

export interface RevocationCheckOptions {
  /** Reference time for the CRL freshness check; defaults to now. `false` skips it. */
  now?: Date | false
}
