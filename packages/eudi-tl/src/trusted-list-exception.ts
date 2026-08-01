/**
 * Base exception for all trusted-list processing failures.
 */
export class TrustedListException extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'TrustedListException'
  }
}

/**
 * The XML could not be parsed as an ETSI TS 119 612 `TrustServiceStatusList`.
 */
export class TrustedListParseException extends TrustedListException {
  constructor(message: string) {
    super(message)
    this.name = 'TrustedListParseException'
  }
}

/**
 * The trusted list's own XAdES/XMLDSig signature is missing, invalid, or does
 * not match a configured trust anchor. Callers MUST treat this as fail-closed:
 * a trusted list whose authenticity cannot be established must not be used to
 * trust credentials.
 */
export class TrustedListSignatureException extends TrustedListException {
  constructor(message: string) {
    super(message)
    this.name = 'TrustedListSignatureException'
  }
}
