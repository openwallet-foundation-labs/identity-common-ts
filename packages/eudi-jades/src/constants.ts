/**
 * JAdES Constants
 *
 * Algorithm definitions and OIDs as per ETSI TS 119 182-1.
 */

/**
 * Commitment type OIDs as per RFC 5035.
 */
export enum CommitmentOIDs {
  /** Proof of origin */
  proofOfOrigin = 'urn:oid:1.2.840.113549.1.9.16.6.1',
  /** Proof of receipt */
  proofOfReceipt = 'urn:oid:1.2.840.113549.1.9.16.6.2',
  /** Proof of delivery */
  proofOfDelivery = 'urn:oid:1.2.840.113549.1.9.16.6.3',
  /** Proof of sender */
  proofOfSender = 'urn:oid:1.2.840.113549.1.9.16.6.4',
  /** Proof of approval */
  proofOfApproval = 'urn:oid:1.2.840.113549.1.9.16.6.5',
  /** Proof of creation */
  proofOfCreation = 'urn:oid:1.2.840.113549.1.9.16.6.6',
}

/**
 * JAdES baseline profiles as per ETSI TS 119 182-1.
 */
export enum JAdESProfile {
  /** Basic - Baseline: basic signature format */
  B_B = 'B-B',
  /** Basic with Time: signatures with timestamp */
  B_T = 'B-T',
  /** Basic Long-Term: signatures with validation data for long-term preservation */
  B_LT = 'B-LT',
  /** Basic Long-Term with Archive timestamps */
  B_LTA = 'B-LTA',
}

/**
 * Detached signature mechanism identifiers as per ETSI TS 119 182-1 Section 5.2.8.
 */
export const DETACHED_MECHANISM_IDS = {
  /** HTTP Headers mechanism */
  httpHeaders: 'http://uri.etsi.org/19182/HttpHeaders',
  /** URI dereferencing mechanism */
  objectByUri: 'http://uri.etsi.org/19182/ObjectIdByURI',
  /** URI digest mechanism */
  objectByUriHash: 'http://uri.etsi.org/19182/ObjectIdByURIHash',
  /** @deprecated Use objectByUriHash. */
  objectDigest: 'http://uri.etsi.org/19182/ObjectIdByURIHash',
} as const

/**
 * Critical header parameters that must be understood.
 * ETSI TS 119 182-1 specifies these parameters as critical.
 */
export const CRITICAL_PARAMETERS = ['sigD', 'b64'] as const
