/**
 * WRPRC Entitlement Constants
 *
 * Entitlement identifiers as defined in ETSI TS 119 475 Annex A.
 * These identifiers define the roles and capabilities of Wallet-Relying Parties.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

// ============================================================================
// OID Base
// ============================================================================

/**
 * Base OID for ETSI WRPA entitlements: 0.4.0.19475
 * id-etsi-wrpa OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0) 19475 }
 */
export const ETSI_WRPA_BASE_OID = '0.4.0.19475'

/**
 * OID arc for entitlements: 0.4.0.19475.1
 */
export const ETSI_WRPA_ENTITLEMENT_ARC = `${ETSI_WRPA_BASE_OID}.1`

// ============================================================================
// WRP Entitlement URIs (A.2)
// ============================================================================

/**
 * Service_Provider - General service provider (A.2.1)
 * OID: id-etsi-wrpa-entitlement 1
 */
export const ENTITLEMENT_SERVICE_PROVIDER = 'https://uri.etsi.org/19475/Entitlement/Service_Provider'

/**
 * QEAA_Provider - Qualified trust service provider issuing qualified electronic attestations of attributes (A.2.2)
 * OID: id-etsi-wrpa-entitlement 2
 */
export const ENTITLEMENT_QEAA_PROVIDER = 'https://uri.etsi.org/19475/Entitlement/QEAA_Provider'

/**
 * Non_Q_EAA_Provider - Trust service provider issuing non-qualified electronic attestations of attributes (A.2.3)
 * OID: id-etsi-wrpa-entitlement 3
 */
export const ENTITLEMENT_NON_Q_EAA_PROVIDER = 'https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider'

/**
 * PUB_EAA_Provider - Public sector body or its agent issuing electronic attestations of attributes from authentic sources (A.2.4)
 * OID: id-etsi-wrpa-entitlement 4
 */
export const ENTITLEMENT_PUB_EAA_PROVIDER = 'https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider'

/**
 * PID_Provider - Provider of person identification data (A.2.5)
 * OID: id-etsi-wrpa-entitlement 5
 */
export const ENTITLEMENT_PID_PROVIDER = 'https://uri.etsi.org/19475/Entitlement/PID_Provider'

/**
 * QCert_for_ESeal_Provider - QTSP issuing qualified certificates for electronic seals (A.2.6)
 * OID: id-etsi-wrpa-entitlement 6
 */
export const ENTITLEMENT_QCERT_FOR_ESEAL_PROVIDER = 'https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider'

/**
 * QCert_for_ESig_Provider - QTSP issuing qualified certificates for electronic signatures (A.2.7)
 * OID: id-etsi-wrpa-entitlement 7
 */
export const ENTITLEMENT_QCERT_FOR_ESIG_PROVIDER = 'https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider'

/**
 * rQSealCDs_Provider - QTSP managing remote qualified electronic seal creation devices (A.2.8)
 * OID: id-etsi-wrpa-entitlement 8
 */
export const ENTITLEMENT_RQSEALCDS_PROVIDER = 'https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider'

/**
 * rQSigCDs_Provider - QTSP managing remote qualified electronic signature creation devices (A.2.9)
 * OID: id-etsi-wrpa-entitlement 9
 */
export const ENTITLEMENT_RQSIGCDS_PROVIDER = 'https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider'

/**
 * ESig_ESeal_Creation_Provider - Non-qualified provider for remote signature/seal creation (A.2.10)
 * OID: id-etsi-wrpa-entitlement 10
 */
export const ENTITLEMENT_ESIG_ESEAL_CREATION_PROVIDER =
  'https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider'

// ============================================================================
// Entitlement Collection
// ============================================================================

/**
 * All standard WRP entitlements defined in ETSI TS 119 475
 */
export const WRP_ENTITLEMENTS = {
  SERVICE_PROVIDER: ENTITLEMENT_SERVICE_PROVIDER,
  QEAA_PROVIDER: ENTITLEMENT_QEAA_PROVIDER,
  NON_Q_EAA_PROVIDER: ENTITLEMENT_NON_Q_EAA_PROVIDER,
  PUB_EAA_PROVIDER: ENTITLEMENT_PUB_EAA_PROVIDER,
  PID_PROVIDER: ENTITLEMENT_PID_PROVIDER,
  QCERT_FOR_ESEAL_PROVIDER: ENTITLEMENT_QCERT_FOR_ESEAL_PROVIDER,
  QCERT_FOR_ESIG_PROVIDER: ENTITLEMENT_QCERT_FOR_ESIG_PROVIDER,
  RQSEALCDS_PROVIDER: ENTITLEMENT_RQSEALCDS_PROVIDER,
  RQSIGCDS_PROVIDER: ENTITLEMENT_RQSIGCDS_PROVIDER,
  ESIG_ESEAL_CREATION_PROVIDER: ENTITLEMENT_ESIG_ESEAL_CREATION_PROVIDER,
} as const

/**
 * List of all standard entitlement URIs
 */
export const ALL_ENTITLEMENTS = Object.values(WRP_ENTITLEMENTS)

/**
 * Entitlements for attestation providers (QEAA, Non-Q EAA, PUB EAA, PID)
 */
export const ATTESTATION_PROVIDER_ENTITLEMENTS = [
  ENTITLEMENT_QEAA_PROVIDER,
  ENTITLEMENT_NON_Q_EAA_PROVIDER,
  ENTITLEMENT_PUB_EAA_PROVIDER,
  ENTITLEMENT_PID_PROVIDER,
] as const

// ============================================================================
// Service Provider Sub-entitlements (A.3)
// ============================================================================

/**
 * Payment Service Provider Sub-entitlements (A.3.1)
 * As defined in ETSI TS 119 495
 */
export const PSP_SUB_ENTITLEMENTS = {
  /** Account Servicing Payment Service Provider */
  ACCOUNT_SERVICING: 'https://uri.etsi.org/19475/SubEntitlement/psp/psp-as',
  /** Payment Initiation Service Provider */
  PAYMENT_INITIATION: 'https://uri.etsi.org/19475/SubEntitlement/psp/psp-pi',
  /** Account Information Service Provider */
  ACCOUNT_INFORMATION: 'https://uri.etsi.org/19475/SubEntitlement/psp/psp-ai',
  /** Payment Service Provider issuing card-based payment instruments */
  CARD_BASED: 'https://uri.etsi.org/19475/SubEntitlement/psp/psp-ic',
  /** Unspecified Payment Service Provider */
  UNSPECIFIED: 'https://uri.etsi.org/19475/SubEntitlement/psp/unspecified',
} as const

/**
 * All PSP sub-entitlement URIs
 */
export const ALL_PSP_SUB_ENTITLEMENTS = Object.values(PSP_SUB_ENTITLEMENTS)

// ============================================================================
// Identifier Type URIs (B.2.5 Class Identifier)
// ============================================================================

/**
 * Identifier type URIs for legal person semantic identifiers
 */
export const IDENTIFIER_TYPES = {
  /** Economic Operator Registration and Identification Number (EORI-No) */
  EORI: 'http://data.europa.eu/eudi/id/EORI-No',
  /** Legal Entity Identifier (LEI) */
  LEI: 'http://data.europa.eu/eudi/id/LEI',
  /** European Unique Identifier (EUID) */
  EUID: 'http://data.europa.eu/eudi/id/EUID',
  /** Value Added Tax Identification Number (VATIN) */
  VATIN: 'http://data.europa.eu/eudi/id/VATIN',
  /** Taxpayer Identification Number (TIN) */
  TIN: 'http://data.europa.eu/eudi/id/TIN',
  /** Excise Number */
  EXCISE: 'http://data.europa.eu/eudi/id/Excise',
} as const

/**
 * Mapping from identifier type URIs to semantic identifier initial characters
 * for legal persons (Table 2, ETSI EN 319 412-1 clause 5.1.4).
 *
 * Note that the TIN type maps to the `VAT` initial characters for legal persons.
 */
export const LEGAL_PERSON_IDENTIFIER_PREFIXES: Record<string, string> = {
  [IDENTIFIER_TYPES.EORI]: 'EOR',
  [IDENTIFIER_TYPES.LEI]: 'LEI',
  [IDENTIFIER_TYPES.EUID]: 'NTR',
  [IDENTIFIER_TYPES.VATIN]: 'VAT',
  [IDENTIFIER_TYPES.TIN]: 'VAT',
  [IDENTIFIER_TYPES.EXCISE]: 'EXC',
}

/**
 * Mapping from identifier type URIs to semantic identifier initial characters
 * for natural persons (Table 4, ETSI EN 319 412-1 clause 5.1.3).
 */
export const NATURAL_PERSON_IDENTIFIER_PREFIXES: Record<string, string> = {
  [IDENTIFIER_TYPES.VATIN]: 'TIN',
  [IDENTIFIER_TYPES.TIN]: 'TIN',
}

// ============================================================================
// Policy Type URIs (B.2.8 Class Policy)
// ============================================================================

/**
 * Policy type URIs
 */
export const POLICY_TYPES = {
  /** Privacy Policy */
  PRIVACY_POLICY: 'http://data.europa.eu/eudi/policy/privacy-policy',
} as const

// ============================================================================
// Certificate Policy OIDs (clause 6.1.3)
// ============================================================================

/**
 * Base OID for WRPRC policies: 0.4.0.19475.3
 */
export const WRPRC_POLICY_BASE_OID = `${ETSI_WRPA_BASE_OID}.3`

/**
 * WRPRC Policy OIDs
 */
export const WRPRC_POLICIES = {
  /** WRPRC provider policy identifier */
  WRPRC_PROVIDER: `${WRPRC_POLICY_BASE_OID}.1`,
} as const

// ============================================================================
// Type Guards and Helpers
// ============================================================================

/**
 * Check if a given URI is a valid WRP entitlement
 */
export function isValidEntitlement(uri: string): boolean {
  return ALL_ENTITLEMENTS.includes(uri as (typeof ALL_ENTITLEMENTS)[number])
}

/**
 * Check if a given URI is a PSP sub-entitlement
 */
export function isPSPSubEntitlement(uri: string): boolean {
  return ALL_PSP_SUB_ENTITLEMENTS.includes(uri as (typeof ALL_PSP_SUB_ENTITLEMENTS)[number])
}

/**
 * Check if entitlements include an attestation provider role
 */
export function hasAttestationProviderEntitlement(entitlements: string[]): boolean {
  return entitlements.some((e) =>
    ATTESTATION_PROVIDER_ENTITLEMENTS.includes(e as (typeof ATTESTATION_PROVIDER_ENTITLEMENTS)[number])
  )
}

/**
 * Get the semantic identifier initial characters for a given identifier type URI
 *
 * @param subjectType - Which mapping to use: Table 2 for legal persons, Table 4 for natural persons
 */
export function getIdentifierPrefix(typeUri: string, subjectType: 'legal' | 'natural' = 'legal'): string | undefined {
  return subjectType === 'legal'
    ? LEGAL_PERSON_IDENTIFIER_PREFIXES[typeUri]
    : NATURAL_PERSON_IDENTIFIER_PREFIXES[typeUri]
}
