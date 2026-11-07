import { base64, compareBytes } from '@owf/identity-common'
import { DOMParser, XMLSerializer } from '@xmldom/xmldom'
import * as xadesjs from 'xadesjs'
import * as xpath from 'xpath'
import { TrustedListSignatureError } from './trusted-list-error'

const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#'

let nodeDependenciesInitialized = false
let installedCrypto: Crypto | undefined

/**
 * Outside the browser, xml-core resolves DOM/XPath implementations through
 * `setNodeDependencies`. Set lazily and once, so importing this package has no
 * side effects until a signature is actually processed.
 */
function ensureNodeDependencies(): void {
  if (nodeDependenciesInitialized) return
  xadesjs.setNodeDependencies({ DOMParser, XMLSerializer, xpath })
  nodeDependenciesInitialized = true
}

/**
 * Install the WebCrypto implementation used to verify trusted list signatures
 * ("bring your own crypto"), for callers that must route verification through a
 * reviewed or policy-constrained engine. Call it once during start-up, before
 * verifying; without it, the global Web Crypto API (`globalThis.crypto`,
 * available in Node >= 20 and browsers) is used.
 *
 * Process-wide by necessity, not by design: xadesjs exposes a single global
 * crypto engine rather than a per-call context
 * (see {@link https://github.com/PeculiarVentures/xmldsigjs/issues/119}).
 * A per-invocation option would look isolated while still swapping that global,
 * so concurrent verifications with different engines would race; it is
 * deliberately not offered. Should upstream gain per-call crypto, accepting it
 * as a verification option is an additive, non-breaking change.
 */
export function setTrustedListCrypto(crypto: Crypto): void {
  ensureNodeDependencies()
  xadesjs.Application.setEngine('eudi-tl', crypto)
  installedCrypto = crypto
}

/**
 * Make sure a crypto engine is installed before verifying. A caller-installed
 * engine is never replaced — falling back to `globalThis.crypto` on every call
 * that does not opt in would silently undo {@link setTrustedListCrypto}.
 */
function ensureXmlSignatureEngine(): void {
  ensureNodeDependencies()
  if (!installedCrypto) setTrustedListCrypto(globalThis.crypto)
}

export interface VerifyTrustedListOptions {
  /**
   * DER-encoded certificates the trusted list's signer certificate must match.
   * When provided, verification fails closed unless the signature verifies
   * with the key of one of these anchors — establishing that the list was
   * signed by the expected scheme operator, not merely by *some* key. An empty
   * list fails closed too.
   *
   * When omitted, only the cryptographic validity of the enveloped signature
   * is checked; that proves integrity, NOT trust. Production callers should
   * always pin the scheme operator certificate(s).
   */
  trustAnchors?: Uint8Array[]
}

export interface VerifyTrustedListResult {
  /** base64-encoded DER of the signer certificate from the signature KeyInfo, whose key verified the signature. */
  signerCertificateBase64: string
}

/** A certificate of the signature KeyInfo, as xmldsigjs parses it. */
interface KeyInfoCertificate {
  GetRaw(): Uint8Array
  exportKey(algorithm: Algorithm): Promise<CryptoKey>
}

/**
 * xmldsigjs accepts a signature that any key in the KeyInfo verifies, but the KeyInfo is not signed: whoever passes
 * the list can add their own key next to a pinned certificate. So the signature is verified with the key of the
 * `signerCertificate` only.
 */
class SignerCertificateSignedXml extends xadesjs.SignedXml {
  signerCertificate?: KeyInfoCertificate

  /** The certificates of the X509Data elements in the KeyInfo. */
  keyInfoCertificates(): KeyInfoCertificate[] {
    return this.XmlSignature.KeyInfo.GetIterator().flatMap(
      (clause) => (clause as { Certificates?: KeyInfoCertificate[] }).Certificates ?? []
    )
  }

  protected override async GetPublicKeys(): Promise<CryptoKey[]> {
    if (!this.signerCertificate || !this.Algorithm) return []
    // exportKey sets the namedCurve of an ECDSA algorithm on the object it is given
    const key = await this.signerCertificate.exportKey({ ...this.Algorithm })
    if (!key.algorithm.name.startsWith('RSA')) return [key]
    // As in xmldsigjs, an RSA key is imported again with the hash of the signature algorithm
    const subtle = xadesjs.Application.crypto.subtle
    const spki = await subtle.exportKey('spki', key)
    return [await subtle.importKey('spki', spki, this.Algorithm as RsaHashedImportParams, true, ['verify'])]
  }
}

/**
 * Verify the enveloped XAdES/XMLDSig signature of an ETSI TS 119 612 Trusted
 * List. Throws {@link TrustedListSignatureError} when the signature is
 * missing, invalid, not the only `ds:Signature` of the list, or (with
 * `trustAnchors`) not verified by the key of a pinned scheme operator
 * certificate.
 *
 * Verified against a standard eIDAS national trusted list (RSA-SHA512,
 * exclusive C14N, XAdES SignedProperties).
 *
 * Verification runs on the global Web Crypto API unless another implementation
 * was installed with {@link setTrustedListCrypto}.
 */
export async function verifyTrustedListSignature(
  xml: string,
  options: VerifyTrustedListOptions = {}
): Promise<VerifyTrustedListResult> {
  ensureXmlSignatureEngine()

  const { trustAnchors } = options
  if (trustAnchors?.length === 0) {
    throw new TrustedListSignatureError('No trust anchors are configured, so no signer certificate can be trusted')
  }

  const doc = new DOMParser().parseFromString(xml, 'application/xml')
  const signatures = doc.getElementsByTagNameNS(XMLDSIG_NS, 'Signature')
  if (signatures.length === 0) {
    throw new TrustedListSignatureError('No ds:Signature found in the trusted list')
  }
  // ETSI TS 119 612 clause 5.7.1: one enveloped signature. The enveloped-signature transform leaves out every
  // ds:Signature child of the root, so the content of another one would not be signed.
  if (signatures.length > 1 || signatures[0].parentNode !== doc.documentElement) {
    throw new TrustedListSignatureError('The trusted list must have exactly one ds:Signature, as a child of its root')
  }

  // xadesjs is typed against the lib.dom DOM; @xmldom implements the same
  // shape at runtime, so bridge the two nominal types at this boundary only.
  const signedXml = new SignerCertificateSignedXml(doc as unknown as Document)
  signedXml.LoadXml(signatures[0] as unknown as Element)

  const certificates = signedXml.keyInfoCertificates()
  if (certificates.length === 0) {
    throw new TrustedListSignatureError('Trusted list signature has no X509Certificate in KeyInfo')
  }
  const candidates = trustAnchors
    ? certificates.filter((certificate) => trustAnchors.some((anchor) => compareBytes(anchor, certificate.GetRaw())))
    : certificates.slice(0, 1)
  if (candidates.length === 0) {
    throw new TrustedListSignatureError('Trusted list signer certificate is not among the configured trust anchors')
  }

  for (const candidate of candidates) {
    signedXml.signerCertificate = candidate
    let valid: boolean
    try {
      valid = await signedXml.Verify()
    } catch (error) {
      throw new TrustedListSignatureError(
        `Trusted list signature could not be verified: ${error instanceof Error ? error.message : String(error)}`,
        { cause: error }
      )
    }
    if (valid) return { signerCertificateBase64: base64.encode(candidate.GetRaw()) }
  }

  throw new TrustedListSignatureError('Trusted list signature is invalid')
}
