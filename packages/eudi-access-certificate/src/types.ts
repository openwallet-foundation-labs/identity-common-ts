import type { JsonWebKey } from '@owf/identity-common'
import type {
  Certificate,
  CertificateInput,
  KeyIdentifierHasher,
  KeyUsageType,
  PreparedSignedStructure,
  SignatureAlgorithm,
  SignOptions,
} from '@owf/x509'
import type { AccessCertificatePolicy, AccessCertificateSubjectType } from './constants'

// ============================================================================
// Profile view of a certificate
// ============================================================================

/**
 * Semantic identifier as defined in ETSI EN 319 412-1 clause 5.1.3 (natural persons,
 * `serialNumber`) and clause 5.1.4 (legal persons, `organizationIdentifier`),
 * e.g. `VATBE-0876866054`, `LEIXG-529900T8BM49AURSDO55` or `PNODE-12345678`.
 */
export interface SemanticIdentifier {
  /** The complete attribute value */
  value: string
  /** 3 character identity type reference (e.g. `VAT`, `NTR`, `PSD`, `LEI`, `PAS`, `IDC`, `PNO`, `TAX`, `TIN`) or a 2 character national scheme followed by `:` */
  type: string
  /** ISO 3166-1 country code (or `EU` / `XG`); Greece is `EL` */
  countryCode: string
  /** Optional ISO 3166-2 subdivision code following a `+` */
  subdivision?: string
  /** The identifier within the scheme */
  identifier: string
}

/** GEN-6.6.1-07: contact information of the wallet-relying party taken from the SAN */
export interface AccessCertificateContact {
  /** Website for helpdesk and support (SAN uniformResourceIdentifier) */
  uris: string[]
  /** Email address (SAN rfc822Name) */
  emails: string[]
  /** Phone number (SAN otherName with type-id id-at-telephoneNumber) */
  phoneNumbers: string[]
}

/**
 * A wallet-relying party access certificate: the generic X.509 certificate plus the
 * information ETSI TS 119 411-8 gives meaning to.
 */
export interface AccessCertificate {
  /** The underlying X.509 certificate, e.g. for signature and revocation checks with `@owf/x509` */
  certificate: Certificate
  /** The ETSI TS 119 411-8 policies found in the certificate */
  policies: AccessCertificatePolicy[]
  /**
   * Whether the certificate is issued to a natural or legal person. Derived from the
   * TS 119 411-8 policy, falling back to the subject attributes.
   */
  subjectType?: AccessCertificateSubjectType
  /** Whether a QCP-n-eudiwrp or QCP-l-eudiwrp policy is present */
  qualified: boolean
  /** Parsed semantic identifier of the wallet-relying party (`organizationIdentifier` or `serialNumber`) */
  subjectIdentifier?: SemanticIdentifier
  contact: AccessCertificateContact
}

// ============================================================================
// Validation
// ============================================================================

export type AccessCertificateValidationSeverity = 'error' | 'warning'

export interface AccessCertificateValidationIssue<Code extends string = string> {
  code: Code
  severity: AccessCertificateValidationSeverity
  message: string
  /** Requirement identifier of the originating specification, e.g. `GEN-6.6.1-05` */
  requirement?: string
}

export interface AccessCertificateValidationOptions {
  /** Reference time for the validity period check; defaults to now. Pass `false` to skip it. */
  now?: Date | false
  /**
   * GEN-6.6.1-03 allows a TSP allocated policy OID instead of the TS 119 411-8 OIDs.
   * Certificates carrying one of these are accepted without a TS 119 411-8 policy.
   */
  acceptedPolicyOids?: string[]
  /** Expected subject type, overriding the one derived from the certificate */
  subjectType?: AccessCertificateSubjectType
}

// ============================================================================
// Creation
// ============================================================================

/** Subject of an access certificate issued to a legal person (ETSI EN 319 412-3) */
export interface LegalPersonSubjectInput {
  /** GEN-6.1.1-04: trade name or service name that is recognisable to the user */
  commonName: string
  organizationName: string
  /** GEN-6.6.1-05: semantic identifier per ETSI EN 319 412-1 clause 5.1.4 */
  organizationIdentifier: string
  /** ISO 3166-1 alpha-2 country code */
  countryName: string
  /** GEN-6.6.1-08: differentiate instances of the same organization */
  organizationalUnitNames?: string[]
  localityName?: string
  stateOrProvinceName?: string
}

/** Subject of an access certificate issued to a natural person (ETSI EN 319 412-2) */
export interface NaturalPersonSubjectInput {
  commonName: string
  givenName?: string
  surname?: string
  pseudonym?: string
  /** Semantic identifier per ETSI EN 319 412-1 clause 5.1.3 */
  serialNumber?: string
  /** ISO 3166-1 alpha-2 country code */
  countryName: string
  organizationalUnitNames?: string[]
}

interface BaseAccessCertificateOptions {
  /** Additional, TSP allocated policy OIDs (GEN-6.6.1-03) */
  additionalPolicyOids?: string[]
  /** GEN-6.6.1-06: URL of the CPS of the access certificate provider */
  cpsUri: string
  /** GEN-6.6.1-07: at least one website, email address or phone number */
  contact: Partial<AccessCertificateContact>
  /** Additional DNS names, e.g. for the OpenID4VP `x509_san_dns` client identifier prefix */
  dnsNames?: string[]
  /** Public key of the wallet-relying party as DER SubjectPublicKeyInfo or public JWK */
  subjectPublicKey: Uint8Array | JsonWebKey
  /** Certificate of the issuing CA; supplies the issuer name and authority key identifier */
  issuerCertificate: CertificateInput
  /** Positive serial number as bytes or hex string (at most 20 octets) */
  serialNumber: Uint8Array | string
  notBefore: Date
  notAfter: Date
  /** Algorithm the issuing CA key signs with */
  signatureAlgorithm: SignatureAlgorithm
  /** Defaults to `['digitalSignature']` */
  keyUsage?: KeyUsageType[]
  extendedKeyUsage?: string[]
  crlDistributionPoints?: string[]
  ocspUrls?: string[]
  caIssuersUrls?: string[]
  /** Extra QC statement content for qualified policies */
  qcStatements?: {
    /** Add id-etsi-qcs-QcSSCD */
    qcSSCD?: boolean
    pds?: { url: string; language: string }[]
    legislationCountries?: string[]
  }
  /** Adds a subject key identifier extension when provided */
  hasher?: KeyIdentifierHasher
}

export interface LegalPersonAccessCertificateOptions extends BaseAccessCertificateOptions {
  policy: 'NCP-l-eudiwrp' | 'QCP-l-eudiwrp'
  subject: LegalPersonSubjectInput
}

export interface NaturalPersonAccessCertificateOptions extends BaseAccessCertificateOptions {
  policy: 'NCP-n-eudiwrp' | 'QCP-n-eudiwrp'
  subject: NaturalPersonSubjectInput
}

export type PrepareAccessCertificateOptions =
  | LegalPersonAccessCertificateOptions
  | NaturalPersonAccessCertificateOptions

export type CreateAccessCertificateOptions = PrepareAccessCertificateOptions & SignOptions

export type PreparedAccessCertificate = PreparedSignedStructure
