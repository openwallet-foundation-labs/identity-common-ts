import { base64, compareBytes } from '@owf/identity-common'
import { DOMParser, XMLSerializer, type Document as XmlDocument, type Element as XmlElement } from '@xmldom/xmldom'
import * as xadesjs from 'xadesjs'
import * as xpath from 'xpath'
import { TrustedListSignatureError } from './trusted-list-error'

const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#'
const TSL_NS = 'http://uri.etsi.org/02231/v2#'
const XADES_NS = 'http://uri.etsi.org/01903/v1.3.2#'
const SIGNED_PROPERTIES_TYPE = 'http://uri.etsi.org/01903#SignedProperties'

/** Canonicalization methods: exclusive C14N, C14N 1.0 and C14N 1.1, with and without comments. */
const CANONICALIZATIONS = new Set([
  'http://www.w3.org/2001/10/xml-exc-c14n#',
  'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
  'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
  'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
  'http://www.w3.org/2006/12/xml-c14n11',
  'http://www.w3.org/2006/12/xml-c14n11#WithComments',
])

const ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'

/** Transforms of a reference: the enveloped signature and canonicalization. */
const TRANSFORMS = new Set([ENVELOPED_SIGNATURE, ...CANONICALIZATIONS])

/** The elements with this `Id`, `ID` or `id`: the attributes by which xmldsigjs resolves a `#` reference. */
function elementsWithId(doc: XmlDocument, id: string): XmlElement[] {
  return Array.from(doc.getElementsByTagName('*')).filter((element) =>
    ['Id', 'ID', 'id'].some((name) => element.hasAttribute(name) && element.getAttribute(name) === id)
  )
}

/**
 * Check the signature against the profile of ETSI TS 119 612 before xmldsigjs verifies it.
 *
 * xmldsigjs applies the transforms of every reference to the document before it checks the signature value, so whoever
 * serves the list chooses what runs: the XPath transform, evaluated once per node, takes quadratic time on a large
 * list (XML Signature Best Practices section 2.1). Only the enveloped-signature transform and canonicalization are
 * accepted, each at most once per reference, as each runs on the whole referenced element, and xmldsigjs searches the
 * whole document for the target of each `#` reference.
 *
 * ETSI TS 119 612 V2.4.1 Annex B.1.0: the signature references the `TrustServiceStatusList` that envelops it. A `#`
 * reference resolves to any element with that `Id`, so a list signed by reference to another element, or with an `Id`
 * that occurs twice, could be wrapped into another root, whose content `parseTrustedList` would then read (XML
 * Signature Best Practices section 3.1). So one reference is `URI=""` or the `Id` of the root, which no other element
 * has, and at most one other reference is to the XAdES `SignedProperties` of the signature.
 */
function assertSignatureProfile(doc: XmlDocument, signature: XmlElement): void {
  const root = doc.documentElement
  if (
    root?.namespaceURI !== TSL_NS ||
    root.localName !== 'TrustServiceStatusList' ||
    doc.getElementsByTagNameNS(TSL_NS, 'TrustServiceStatusList').length !== 1
  ) {
    throw new TrustedListSignatureError('The trusted list must be the root and the only TrustServiceStatusList')
  }

  for (const method of Array.from(signature.getElementsByTagNameNS(XMLDSIG_NS, 'CanonicalizationMethod'))) {
    const algorithm = method.getAttribute('Algorithm') ?? ''
    if (!CANONICALIZATIONS.has(algorithm)) {
      throw new TrustedListSignatureError(
        `Trusted list signature uses the canonicalization ${JSON.stringify(algorithm)}, which is not allowed`
      )
    }
  }
  for (const transform of Array.from(signature.getElementsByTagNameNS(XMLDSIG_NS, 'Transform'))) {
    const algorithm = transform.getAttribute('Algorithm') ?? ''
    if (!TRANSFORMS.has(algorithm)) {
      throw new TrustedListSignatureError(
        `Trusted list signature uses the transform ${JSON.stringify(algorithm)}, which is not allowed`
      )
    }
  }

  const signedInfo = Array.from(signature.childNodes).find(
    (node): node is XmlElement =>
      (node as XmlElement).namespaceURI === XMLDSIG_NS && (node as XmlElement).localName === 'SignedInfo'
  )
  const references = Array.from(signedInfo?.getElementsByTagNameNS(XMLDSIG_NS, 'Reference') ?? [])
  if (references.length > 2) {
    throw new TrustedListSignatureError('Trusted list signature has more than two references')
  }
  const rootId = root.getAttribute('Id')
  let referencesList = false
  for (const reference of references) {
    const algorithms = Array.from(reference.getElementsByTagNameNS(XMLDSIG_NS, 'Transform')).map((transform) =>
      transform.getAttribute('Algorithm')
    )
    if (
      algorithms.filter((algorithm) => algorithm === ENVELOPED_SIGNATURE).length > 1 ||
      algorithms.filter((algorithm) => algorithm && CANONICALIZATIONS.has(algorithm)).length > 1
    ) {
      throw new TrustedListSignatureError(
        'Trusted list signature applies the enveloped-signature transform or a canonicalization twice to a reference'
      )
    }

    const uri = reference.getAttribute('URI')
    if (uri === '' || (rootId && uri === `#${rootId}` && elementsWithId(doc, rootId).length === 1)) {
      if (referencesList) throw new TrustedListSignatureError('Trusted list signature references the list twice')
      referencesList = true
      continue
    }
    const targets =
      reference.getAttribute('Type') === SIGNED_PROPERTIES_TYPE && uri?.startsWith('#')
        ? elementsWithId(doc, uri.slice(1))
        : []
    if (targets.length !== 1 || targets[0].namespaceURI !== XADES_NS || targets[0].localName !== 'SignedProperties') {
      throw new TrustedListSignatureError(
        `Trusted list signature references ${JSON.stringify(uri)}, which is neither the list nor its signed properties`
      )
    }
  }
  if (!referencesList) {
    throw new TrustedListSignatureError('Trusted list signature does not reference the list')
  }
}

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
 * missing, invalid, not the only `ds:Signature` of the list, uses a transform
 * other than the enveloped signature and canonicalization, does not reference
 * the list itself, or (with `trustAnchors`) is not verified by the key of a
 * pinned scheme operator certificate.
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
  assertSignatureProfile(doc, signatures[0])

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
