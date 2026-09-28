/** X.520 attribute types and PKCS#9 emailAddress, as used in distinguished names */
export const ATTRIBUTE_TYPES = {
  commonName: '2.5.4.3',
  surname: '2.5.4.4',
  serialNumber: '2.5.4.5',
  countryName: '2.5.4.6',
  localityName: '2.5.4.7',
  stateOrProvinceName: '2.5.4.8',
  streetAddress: '2.5.4.9',
  organizationName: '2.5.4.10',
  organizationalUnitName: '2.5.4.11',
  title: '2.5.4.12',
  postalCode: '2.5.4.17',
  telephoneNumber: '2.5.4.20',
  givenName: '2.5.4.42',
  initials: '2.5.4.43',
  generationQualifier: '2.5.4.44',
  pseudonym: '2.5.4.65',
  organizationIdentifier: '2.5.4.97',
  emailAddress: '1.2.840.113549.1.9.1',
} as const

export type AttributeName = keyof typeof ATTRIBUTE_TYPES

/** Policy qualifier identifiers (RFC 5280 clause 4.2.1.4) */
export const POLICY_QUALIFIERS = {
  cps: '1.3.6.1.5.5.7.2.1',
  unotice: '1.3.6.1.5.5.7.2.2',
} as const

/** Access methods for the Authority Information Access extension (RFC 5280 clause 4.2.2.1) */
export const ACCESS_METHODS = {
  ocsp: '1.3.6.1.5.5.7.48.1',
  caIssuers: '1.3.6.1.5.5.7.48.2',
} as const

/** QCStatements extension (RFC 3739) and statements from ETSI EN 319 412-5 */
export const QC_STATEMENTS = {
  extension: '1.3.6.1.5.5.7.1.3',
  /** id-etsi-qcs-QcCompliance */
  qcCompliance: '0.4.0.1862.1.1',
  /** id-etsi-qcs-QcSSCD */
  qcSSCD: '0.4.0.1862.1.4',
  /** id-etsi-qcs-QcPDS */
  qcPDS: '0.4.0.1862.1.5',
  /** id-etsi-qcs-QcType */
  qcType: '0.4.0.1862.1.6',
  /** id-etsi-qcs-QcCClegislation */
  qcCClegislation: '0.4.0.1862.1.7',
} as const

/** QcType values (ETSI EN 319 412-5 clause 4.2.3) */
export const QC_TYPES = {
  esign: '0.4.0.1862.1.6.1',
  eseal: '0.4.0.1862.1.6.2',
  web: '0.4.0.1862.1.6.3',
} as const

export type QcType = keyof typeof QC_TYPES

/** Signature algorithms supported for creating and describing certificates and CRLs */
export const SIGNATURE_ALGORITHMS = {
  ES256: { oid: '1.2.840.10045.4.3.2', hash: 'SHA-256', family: 'ecdsa' },
  ES384: { oid: '1.2.840.10045.4.3.3', hash: 'SHA-384', family: 'ecdsa' },
  ES512: { oid: '1.2.840.10045.4.3.4', hash: 'SHA-512', family: 'ecdsa' },
  RS256: { oid: '1.2.840.113549.1.1.11', hash: 'SHA-256', family: 'rsa' },
  RS384: { oid: '1.2.840.113549.1.1.12', hash: 'SHA-384', family: 'rsa' },
  RS512: { oid: '1.2.840.113549.1.1.13', hash: 'SHA-512', family: 'rsa' },
} as const

export type SignatureAlgorithm = keyof typeof SIGNATURE_ALGORITHMS

/** Public key algorithm and curve identifiers */
export const KEY_ALGORITHMS = {
  ecPublicKey: '1.2.840.10045.2.1',
  rsaEncryption: '1.2.840.113549.1.1.1',
  'P-256': '1.2.840.10045.3.1.7',
  'P-384': '1.3.132.0.34',
  'P-521': '1.3.132.0.35',
} as const

/** CRL entry revocation reasons (RFC 5280 clause 5.3.1) */
export const CRL_REASONS = {
  unspecified: 0,
  keyCompromise: 1,
  cACompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  certificateHold: 6,
  removeFromCRL: 8,
  privilegeWithdrawn: 9,
  aACompromise: 10,
} as const

export type CrlReason = keyof typeof CRL_REASONS
