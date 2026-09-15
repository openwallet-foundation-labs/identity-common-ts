import type { CoseKey, DigestAlgorithm, Mac0Context, MacAlgorithm, Sign1Context, SignatureAlgorithm } from '@owf/cose'

type MaybePromise<T> = Promise<T> | T

/**
 * HPKE (RFC 9180) cipher suites, identified as `<kem>/<kdf>/<aead>`.
 *
 * ISO/IEC TS 18013-7:2025 C.4 fixes the DC API suite to
 * {@link HpkeSuiteId.DhkemP256HkdfSha256HkdfSha256Aes128Gcm}; the other members exist so the same
 * callbacks can be reused by protocols that negotiate a suite.
 */
export enum HpkeSuiteId {
  /** DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM. */
  DhkemP256HkdfSha256HkdfSha256Aes128Gcm = 'dhkem-p256-hkdf-sha256/hkdf-sha256/aes-128-gcm',

  /** DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM. */
  DhkemP256HkdfSha256HkdfSha256Aes256Gcm = 'dhkem-p256-hkdf-sha256/hkdf-sha256/aes-256-gcm',

  /** DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM. */
  DhkemX25519HkdfSha256HkdfSha256Aes128Gcm = 'dhkem-x25519-hkdf-sha256/hkdf-sha256/aes-128-gcm',
}

export interface HpkeContext {
  /**
   * Suites the `seal` and `open` implementations support. Callers check this before use so an
   * unsupported suite surfaces as a protocol error instead of a callback failure.
   */
  suites: Array<HpkeSuiteId>

  /**
   * Single-shot HPKE seal in base mode (RFC 9180 §6.1).
   */
  seal: (input: {
    suite: HpkeSuiteId
    recipientPublicKey: CoseKey
    info: Uint8Array
    aad?: Uint8Array
    plaintext: Uint8Array
  }) => MaybePromise<{ enc: Uint8Array; ciphertext: Uint8Array }>

  /**
   * Single-shot HPKE open in base mode (RFC 9180 §6.1). `enc` is the raw serialized encapsulated
   * key for the suite's KEM (uncompressed SEC1 point for the DHKEM(P-256) suites).
   */
  open: (input: {
    suite: HpkeSuiteId
    /**
     * The recipient key. Implementations that keep private keys inside a key management system are
     * passed the public key and resolve the associated private key based on its `keyId`, the same
     * way {@link Sign1Context.sign} resolves a signing key.
     */
    recipientKey: CoseKey
    enc: Uint8Array
    info: Uint8Array
    aad?: Uint8Array
    ciphertext: Uint8Array
  }) => MaybePromise<Uint8Array>
}

export interface MdocContext {
  fetch: typeof fetch
  crypto: {
    random: (length: number) => Uint8Array
    digest: (input: { digestAlgorithm: DigestAlgorithm; bytes: Uint8Array }) => MaybePromise<Uint8Array>
    hdkf: (input: {
      digestAlgorithm?: DigestAlgorithm
      privateKey: Uint8Array
      publicKey: Uint8Array
      salt: Uint8Array
      info: Uint8Array
    }) => MaybePromise<Uint8Array>

    /**
     * Required for the ISO 18013-7 Annex C (`org-iso-mdoc`) DC API flows only.
     */
    hpke?: HpkeContext
  }

  cose: {
    sign1: {
      sign: Sign1Context['sign']
      verify: Sign1Context['verify']
    }

    mac0: Mac0Context
  }

  x509: {
    /**
     * The values of a field of the subject distinguished name of a certificate, e.g. `C` or `ST`.
     */
    getSubjectNameField: (options: { certificate: Uint8Array; field: string }) => string[]
    getPublicKey: (options: {
      certificate: Uint8Array
      algorithm?: SignatureAlgorithm | MacAlgorithm
    }) => Promise<CoseKey>

    /**
     * Verify a X.509 certificate chain, returning it with the leaf first and the trusted root last.
     */
    verifyCertificateChain: (input: {
      trustedCertificates: Uint8Array[]
      x5chain: Uint8Array[]
      now?: Date
    }) => MaybePromise<{ chain: Uint8Array[] }>

    getCertificateData: (input: { certificate: Uint8Array }) => MaybePromise<{
      issuerName: string
      subjectName: string
      serialNumber: string
      thumbprint: string
      notBefore: Date
      notAfter: Date
      pem: string
    }>
  }
}
