import { base64 } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { loadTrustedList, setTrustedListCrypto, TrustedListSignatureError, verifyTrustedListSignature } from '../index'
import { LOTL_POINTER_CERT_BASE64, SIGNED_TSL_XML, SIGNER_CERT_BASE64, UNSIGNED_TSL_XML } from './fixtures.mjs'

const trustAnchors = [base64.decode(SIGNER_CERT_BASE64)]

// A granted CA that the scheme operator did not sign
const EVIL_PROVIDER = `<tsl:TrustServiceProvider xmlns:tsl="http://uri.etsi.org/02231/v2#"><tsl:TSPInformation><tsl:TSPName><tsl:Name xml:lang="en">Evil CA</tsl:Name></tsl:TSPName></tsl:TSPInformation><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier><tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509Certificate>${LOTL_POINTER_CERT_BASE64}</tsl:X509Certificate></tsl:DigitalId></tsl:ServiceDigitalIdentity><tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</tsl:ServiceStatus></tsl:ServiceInformation></tsl:TSPService></tsl:TSPServices></tsl:TrustServiceProvider>`

/**
 * Signature verification uses a small signed sample generated once by
 * `scripts/generate-test-fixtures.mts` (enveloped XAdES, RSA-SHA256, exclusive
 * C14N) — the suite only verifies, it never signs.
 */
describe('verifyTrustedListSignature', () => {
  it('verifies the enveloped XAdES signature and reports the signer certificate', async () => {
    const result = await verifyTrustedListSignature(SIGNED_TSL_XML)
    expect(result.signerCertificateBase64).toBe(SIGNER_CERT_BASE64)
  })

  it('accepts the signature when the signer certificate is a pinned trust anchor', async () => {
    await expect(
      verifyTrustedListSignature(SIGNED_TSL_XML, {
        trustAnchors: [base64.decode(SIGNER_CERT_BASE64)],
      })
    ).resolves.toBeDefined()
  })

  it('fails closed when the signer certificate is not a pinned trust anchor', async () => {
    await expect(
      verifyTrustedListSignature(SIGNED_TSL_XML, {
        trustAnchors: [new Uint8Array([1, 2, 3])],
      })
    ).rejects.toThrow(TrustedListSignatureError)
  })

  // The KeyInfo is not signed, so whoever passes the list can put a pinned certificate in it next to the certificate
  // of their own key (ETSI TS 119 612 clause 5.7.1: the list is signed by the scheme operator)
  it('fails closed when a pinned certificate is in the KeyInfo but another key signed the list', async () => {
    const forged = SIGNED_TSL_XML.replace(
      '<ds:X509Data>',
      `<ds:X509Data><ds:X509Certificate>${LOTL_POINTER_CERT_BASE64}</ds:X509Certificate>`
    )

    await expect(
      verifyTrustedListSignature(forged, { trustAnchors: [base64.decode(LOTL_POINTER_CERT_BASE64)] })
    ).rejects.toThrow('Trusted list signature is invalid')
    // Without trust anchors, the reported signer certificate is the one whose key verified the signature
    await expect(verifyTrustedListSignature(forged)).rejects.toThrow('Trusted list signature is invalid')
    await expect(verifyTrustedListSignature(forged, { trustAnchors })).resolves.toEqual({
      signerCertificateBase64: SIGNER_CERT_BASE64,
    })
  })

  it('fails closed with an empty list of trust anchors', async () => {
    await expect(verifyTrustedListSignature(SIGNED_TSL_XML, { trustAnchors: [] })).rejects.toThrow(
      TrustedListSignatureError
    )
  })

  // The enveloped-signature transform leaves out every ds:Signature child of the root, so their content is not signed
  it('rejects a list with a second ds:Signature', async () => {
    const wrapped = SIGNED_TSL_XML.replace(
      '</tsl:TrustServiceStatusList>',
      `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${EVIL_PROVIDER}</ds:Signature></tsl:TrustServiceStatusList>`
    )

    await expect(verifyTrustedListSignature(wrapped, { trustAnchors })).rejects.toThrow(TrustedListSignatureError)
  })

  // XML Signature Best Practices section 2.1: xmldsigjs applies the transforms before it checks the signature value,
  // so the XPath transform, evaluated once per node, would run on whatever whoever serves the list put there
  it('rejects a transform other than the enveloped signature and canonicalization', async () => {
    const xpathTransform = SIGNED_TSL_XML.replace(
      '<ds:Transforms>',
      '<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>count(//. | //@*) &gt; 0</ds:XPath></ds:Transform>'
    )

    await expect(verifyTrustedListSignature(xpathTransform, { trustAnchors })).rejects.toThrow(
      'Trusted list signature uses the transform "http://www.w3.org/TR/1999/REC-xpath-19991116", which is not allowed'
    )
  })

  // Each transform runs on the whole referenced element, so repeating an allowed one costs as much
  it('rejects a transform repeated in a reference', async () => {
    const repeated = SIGNED_TSL_XML.replace(
      '<ds:Transforms>',
      '<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
    )

    await expect(verifyTrustedListSignature(repeated, { trustAnchors })).rejects.toThrow(
      'Trusted list signature applies the enveloped-signature transform or a canonicalization twice to a reference'
    )
  })

  // xmldsigjs searches the whole document for the target of each reference
  it('rejects more references than one to the list and one to its signed properties', async () => {
    const signedPropertiesReference = SIGNED_TSL_XML.match(/<ds:Reference URI="#xades-[\s\S]*?<\/ds:Reference>/)?.[0]
    const threeReferences = SIGNED_TSL_XML.replace('</ds:SignedInfo>', `${signedPropertiesReference}</ds:SignedInfo>`)
    const listTwice = SIGNED_TSL_XML.replace(/URI="#xades-[^"]+"/, 'URI=""')

    await expect(verifyTrustedListSignature(threeReferences, { trustAnchors })).rejects.toThrow(
      'Trusted list signature has more than two references'
    )
    await expect(verifyTrustedListSignature(listTwice, { trustAnchors })).rejects.toThrow(
      'Trusted list signature references the list twice'
    )
  })

  it('rejects a canonicalization method that is not a canonicalization', async () => {
    const xslt = SIGNED_TSL_XML.replace(
      /<ds:CanonicalizationMethod Algorithm="[^"]*"\/>/,
      '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"/>'
    )

    await expect(verifyTrustedListSignature(xslt, { trustAnchors })).rejects.toThrow(
      'Trusted list signature uses the canonicalization "http://www.w3.org/TR/1999/REC-xslt-19991116", which is not allowed'
    )
  })

  // ETSI TS 119 612 V2.4.1 Annex B.1.0: a reference to the TrustServiceStatusList that envelops the signature. Content
  // outside the referenced element is not signed, so a list signed once could be wrapped into another root.
  it('rejects a signature that references another element than the list', async () => {
    const otherElement = SIGNED_TSL_XML.replace(
      '<tsl:SchemeInformation>',
      '<tsl:SchemeInformation Id="scheme">'
    ).replace('<ds:Reference URI="">', '<ds:Reference URI="#scheme">')

    await expect(verifyTrustedListSignature(otherElement, { trustAnchors })).rejects.toThrow(
      'Trusted list signature references "#scheme", which is neither the list nor its signed properties'
    )
  })

  it('rejects a reference typed as signed properties that names another element', async () => {
    const signatureId = SIGNED_TSL_XML.match(/<ds:Signature Id="([^"]+)"/)?.[1]
    const notSignedProperties = SIGNED_TSL_XML.replace(/URI="#xades-[^"]+"/, `URI="#${signatureId}"`)

    await expect(verifyTrustedListSignature(notSignedProperties, { trustAnchors })).rejects.toThrow(
      `Trusted list signature references "#${signatureId}", which is neither the list nor its signed properties`
    )
  })

  it('rejects a signature without a reference to the list', async () => {
    const onlySignedProperties = SIGNED_TSL_XML.replace(/<ds:Reference URI="">[\s\S]*?<\/ds:Reference>/, '')

    await expect(verifyTrustedListSignature(onlySignedProperties, { trustAnchors })).rejects.toThrow(
      'Trusted list signature does not reference the list'
    )
  })

  // A reference by Id resolves to any element with that Id
  it('rejects a reference to the Id of the root that another element has too', async () => {
    const duplicatedId = SIGNED_TSL_XML.replace(
      '<tsl:SchemeInformation>',
      '<tsl:SchemeInformation Id="TrustServiceStatusList">'
    ).replace('<ds:Reference URI="">', '<ds:Reference URI="#TrustServiceStatusList">')

    await expect(verifyTrustedListSignature(duplicatedId, { trustAnchors })).rejects.toThrow(
      'Trusted list signature references "#TrustServiceStatusList", which is neither the list nor its signed properties'
    )
  })

  // A wrapped list keeps the list that was signed somewhere in the document. The ds:Object is not signed, apart from
  // the signed properties, so the signature still verifies.
  it('rejects a document with a second TrustServiceStatusList', async () => {
    const nested = SIGNED_TSL_XML.replace(
      '<ds:Object>',
      '<ds:Object><tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#"/>'
    )

    await expect(verifyTrustedListSignature(nested, { trustAnchors })).rejects.toThrow(
      'The trusted list must be the root and the only TrustServiceStatusList'
    )
  })

  it('rejects a tampered document', async () => {
    const tampered = SIGNED_TSL_XML.replace('Test Qualified CA S.A.', 'Evil Qualified CA S.A.')
    expect(tampered).not.toBe(SIGNED_TSL_XML)
    await expect(verifyTrustedListSignature(tampered)).rejects.toThrow(TrustedListSignatureError)
  })

  it('rejects a list without a signature', async () => {
    await expect(verifyTrustedListSignature(UNSIGNED_TSL_XML)).rejects.toThrow(TrustedListSignatureError)
  })

  it('verifies through a caller-installed ("bring your own crypto") engine', async () => {
    // A thin recording wrapper around the global engine: it must be the one
    // actually doing the work, not `globalThis.crypto`.
    const calls: string[] = []
    const subtle = new Proxy(globalThis.crypto.subtle, {
      get(target, property, receiver) {
        calls.push(String(property))
        const value = Reflect.get(target, property, receiver)
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const byoc = new Proxy(globalThis.crypto, {
      get(target, property, receiver) {
        if (property === 'subtle') return subtle
        const value = Reflect.get(target, property, receiver)
        return typeof value === 'function' ? value.bind(target) : value
      },
    }) as Crypto

    setTrustedListCrypto(byoc)
    try {
      const result = await verifyTrustedListSignature(SIGNED_TSL_XML)
      expect(result.signerCertificateBase64).toBe(SIGNER_CERT_BASE64)
      expect(calls).not.toHaveLength(0)

      // The installed engine stays installed: a later call must not silently
      // fall back to the global Web Crypto API.
      calls.length = 0
      await verifyTrustedListSignature(SIGNED_TSL_XML)
      expect(calls).not.toHaveLength(0)
    } finally {
      setTrustedListCrypto(globalThis.crypto)
    }
  })
})

describe('loadTrustedList', () => {
  it('verifies the signature and returns the parsed list', async () => {
    const tl = await loadTrustedList(SIGNED_TSL_XML, {
      trustAnchors: [base64.decode(SIGNER_CERT_BASE64)],
    })
    expect(tl.schemeOperatorName).toBe('Test Scheme Operator')
    expect(tl.providers).toHaveLength(1)
  })

  it('does not parse when the signature check fails', async () => {
    await expect(loadTrustedList(UNSIGNED_TSL_XML, { trustAnchors })).rejects.toThrow(TrustedListSignatureError)
  })

  it('requires trust anchors', async () => {
    // @ts-expect-error trustAnchors is required
    const loading = loadTrustedList(SIGNED_TSL_XML)

    await expect(loading).rejects.toThrow(TrustedListSignatureError)
  })

  // The signature does not cover its own KeyInfo and ds:Object, apart from the signed properties
  it('ignores a trust service provider outside the signed TrustServiceProviderList', async () => {
    const injected = SIGNED_TSL_XML.replace('<ds:Object>', `<ds:Object>${EVIL_PROVIDER}`)

    const tl = await loadTrustedList(injected, { trustAnchors })
    expect(tl.providers.map((provider) => provider.name)).toEqual(['Test Qualified CA S.A.'])
  })
})
