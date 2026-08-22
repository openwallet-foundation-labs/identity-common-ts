import { base64, compareBytes } from '@owf/identity-common'
import { DOMParser, XMLSerializer } from '@xmldom/xmldom'
import * as xadesjs from 'xadesjs'
import * as xpath from 'xpath'
import { TrustedListSignatureException } from './trusted-list-exception'

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
   * When provided, verification fails closed unless the embedded signer
   * certificate equals one of these anchors — establishing that the list was
   * signed by the expected scheme operator, not merely by *some* key.
   *
   * When omitted, only the cryptographic validity of the enveloped signature
   * is checked; that proves integrity, NOT trust. Production callers should
   * always pin the scheme operator certificate(s).
   */
  trustAnchors?: Uint8Array[]
}

export interface VerifyTrustedListResult {
  /** base64-encoded DER of the signer certificate from the signature KeyInfo. */
  signerCertificateBase64: string
}

/**
 * Verify the enveloped XAdES/XMLDSig signature of an ETSI TS 119 612 Trusted
 * List. Throws {@link TrustedListSignatureException} when the signature is
 * missing, invalid, or (with `trustAnchors`) not signed by a pinned scheme
 * operator.
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

  const doc = new DOMParser().parseFromString(xml, 'application/xml')
  const signatures = doc.getElementsByTagNameNS(XMLDSIG_NS, 'Signature')
  if (signatures.length === 0) {
    throw new TrustedListSignatureException('No ds:Signature found in the trusted list')
  }

  // xadesjs is typed against the lib.dom DOM; @xmldom implements the same
  // shape at runtime, so bridge the two nominal types at this boundary only.
  const signedXml = new xadesjs.SignedXml(doc as unknown as Document)
  signedXml.LoadXml(signatures[0] as unknown as Element)

  let valid: boolean
  try {
    valid = await signedXml.Verify()
  } catch (error) {
    throw new TrustedListSignatureException(
      `Trusted list signature could not be verified: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error }
    )
  }
  if (!valid) {
    throw new TrustedListSignatureException('Trusted list signature is invalid')
  }

  // The signature KeyInfo carries the signer certificate (ds:X509Certificate,
  // namespace-scoped so it never picks up service certificates).
  const signerCertEl = signatures[0].getElementsByTagNameNS(XMLDSIG_NS, 'X509Certificate')[0]
  if (!signerCertEl?.textContent) {
    throw new TrustedListSignatureException('Trusted list signature has no X509Certificate in KeyInfo')
  }
  const signerCertificateBase64 = signerCertEl.textContent.replace(/\s/g, '')

  if (options.trustAnchors && options.trustAnchors.length > 0) {
    const signerDer = base64.decode(signerCertificateBase64)
    const trusted = options.trustAnchors.some((anchor) => compareBytes(anchor, signerDer))
    if (!trusted) {
      throw new TrustedListSignatureException(
        'Trusted list signer certificate is not among the configured trust anchors'
      )
    }
  }

  return { signerCertificateBase64 }
}
