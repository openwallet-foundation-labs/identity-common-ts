import { digest } from '@owf/crypto'
import { base64 } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import {
  ATTRIBUTE_TYPES,
  assembleCertificate,
  type CertificateTemplate,
  createCertificate,
  ecdsaP1363ToDer,
  parseCertificate,
  prepareCertificate,
  publicJwkToSpki,
  stringOtherName,
  telephoneNumbers,
  toDer,
  verifyCertificateSignature,
  X509Exception,
} from '../index'
import { generateSubjectKey, webCryptoSigner, webCryptoVerifier } from './crypto.mjs'
import { CA_CERTIFICATE_PEM, CA_PRIVATE_JWK, OPENSSL_LEAF_CERTIFICATE_PEM } from './fixtures.mjs'

describe('parseCertificate', () => {
  const cert = parseCertificate(OPENSSL_LEAF_CERTIFICATE_PEM)

  it('parses the X.509 basics', () => {
    expect(cert.version).toBe(3)
    expect(cert.serialNumber).toBe('0badc0de')
    expect(cert.signatureAlgorithmName).toBe('ES256')
    expect(cert.notBefore.toISOString()).toBe('2026-09-28T19:59:06.000Z')
    expect(cert.notAfter.toISOString()).toBe('2036-09-25T19:59:06.000Z')
    expect(cert.publicKey.jwk).toMatchObject({ kty: 'EC', crv: 'P-256' })
    expect(cert.basicConstraints).toEqual({ cA: false, pathLenConstraint: undefined })
    expect(cert.keyUsage).toEqual(['digitalSignature'])
  })

  it('parses names', () => {
    expect(cert.subject).toMatchObject({
      commonName: 'Example Shop',
      organizationName: 'Example Relying Party GmbH',
      organizationIdentifier: 'VATDE-123456789',
      organizationalUnitNames: ['Online Shop'],
      countryName: 'DE',
    })
    expect(cert.subject.rfc4514).toBe(
      'CN=Example Shop,organizationIdentifier=VATDE-123456789,OU=Online Shop,O=Example Relying Party GmbH,C=DE'
    )
    expect(cert.issuer.commonName).toBe('Example WRP Access CA')
  })

  it('parses policies and subject alternative names', () => {
    expect(cert.policies).toEqual([
      { oid: '0.4.0.194118.1.4', cpsUris: ['https://ca.example.com/cps'], userNotices: [] },
    ])
    expect(cert.subjectAlternativeNames).toMatchObject({
      dnsNames: ['shop.example.com'],
      uris: ['https://shop.example.com/support'],
      emails: ['support@shop.example.com'],
      otherNames: [{ typeId: ATTRIBUTE_TYPES.telephoneNumber, text: '+4930123456' }],
    })
    expect(telephoneNumbers(cert.subjectAlternativeNames)).toEqual(['+4930123456'])
  })

  it('parses revocation, key identifier and QC statement extensions', () => {
    expect(cert.crlDistributionPoints).toEqual(['https://ca.example.com/crl'])
    expect(cert.ocspUrls).toEqual(['https://ocsp.example.com'])
    expect(cert.caIssuersUrls).toEqual(['https://ca.example.com/ca.crt'])
    expect(cert.authorityKeyIdentifier).toBe(parseCertificate(CA_CERTIFICATE_PEM).subjectKeyIdentifier)
    expect(cert.subjectKeyIdentifier).toMatch(/^[0-9a-f]{40}$/)
    expect(cert.qcStatements).toEqual({
      statementIds: ['0.4.0.1862.1.1', '0.4.0.1862.1.6'],
      qcCompliance: true,
      qcSSCD: false,
      qcTypes: ['eseal'],
      pds: [],
      legislationCountries: [],
    })
  })

  it('parses a CA certificate', () => {
    const ca = parseCertificate(CA_CERTIFICATE_PEM)
    expect(ca.basicConstraints).toEqual({ cA: true, pathLenConstraint: 0 })
    expect(ca.keyUsage).toEqual(['crlSign', 'keyCertSign'])
  })

  it('accepts PEM, base64 DER and DER bytes', () => {
    const der = toDer(OPENSSL_LEAF_CERTIFICATE_PEM)
    expect(parseCertificate(der).serialNumber).toBe(cert.serialNumber)
    expect(parseCertificate(base64.encode(der)).serialNumber).toBe(cert.serialNumber)
    expect(parseCertificate(der.buffer as ArrayBuffer).serialNumber).toBe(cert.serialNumber)
    expect(cert.pem.replace(/\s/g, '')).toBe(OPENSSL_LEAF_CERTIFICATE_PEM.replace(/\s/g, ''))
  })

  it('rejects malformed input', () => {
    expect(() => parseCertificate('not a certificate!')).toThrow(X509Exception)
    expect(() => parseCertificate(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]))).toThrow(X509Exception)
    expect(() => parseCertificate('-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----')).toThrow(
      /No PEM block with label "CERTIFICATE"/
    )
  })
})

describe('verifyCertificateSignature', () => {
  it('verifies a certificate signed by the issuer', async () => {
    expect(await verifyCertificateSignature(OPENSSL_LEAF_CERTIFICATE_PEM, CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(
      true
    )
    expect(await verifyCertificateSignature(CA_CERTIFICATE_PEM, CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(true)
  })

  it('rejects a certificate from another issuer', async () => {
    expect(await verifyCertificateSignature(CA_CERTIFICATE_PEM, OPENSSL_LEAF_CERTIFICATE_PEM, webCryptoVerifier)).toBe(
      false
    )
  })

  it('rejects a tampered certificate', async () => {
    const cert = parseCertificate(OPENSSL_LEAF_CERTIFICATE_PEM)
    const tampered = { ...cert, tbsCertificate: cert.tbsCertificate.slice() }
    tampered.tbsCertificate[tampered.tbsCertificate.length - 1] ^= 0xff
    expect(await verifyCertificateSignature(tampered, CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(false)
  })
})

describe('createCertificate', () => {
  const NOT_BEFORE = new Date('2026-10-01T00:00:00Z')
  const NOT_AFTER = new Date('2027-10-01T00:00:00Z')

  async function leafTemplate(): Promise<CertificateTemplate> {
    return {
      subject: [
        ['countryName', 'DE'],
        ['organizationName', 'Example GmbH'],
        ['commonName', 'Example Service'],
      ],
      subjectPublicKey: (await generateSubjectKey()).publicJwk,
      issuerCertificate: CA_CERTIFICATE_PEM,
      serialNumber: 'f00dcafe',
      notBefore: NOT_BEFORE,
      notAfter: NOT_AFTER,
      signatureAlgorithm: 'ES256',
    }
  }

  it('creates an end-entity certificate with the requested extensions', async () => {
    const cert = await createCertificate({
      ...(await leafTemplate()),
      extendedKeyUsage: ['1.3.6.1.5.5.7.3.2'],
      certificatePolicies: [{ oid: '1.2.3.4', cpsUris: ['https://ca.example.com/cps'] }, { oid: '1.2.3.5' }],
      subjectAlternativeNames: {
        dnsNames: ['service.example.com'],
        uris: ['https://service.example.com'],
        emails: ['info@example.com'],
        otherNames: [stringOtherName(ATTRIBUTE_TYPES.telephoneNumber, '+49 30 123456')],
      },
      crlDistributionPoints: ['https://ca.example.com/crl'],
      ocspUrls: ['https://ocsp.example.com'],
      caIssuersUrls: ['https://ca.example.com/ca.crt'],
      qcStatements: { qcTypes: ['esign'], legislationCountries: ['DE'] },
      hasher: digest,
      signer: await webCryptoSigner(CA_PRIVATE_JWK),
    })

    expect(cert.serialNumber).toBe('00f00dcafe')
    expect(cert.subject.rfc4514).toBe('CN=Example Service,O=Example GmbH,C=DE')
    expect(cert.issuer).toEqual(parseCertificate(CA_CERTIFICATE_PEM).subject)
    expect(cert.notBefore).toEqual(NOT_BEFORE)
    expect(cert.notAfter).toEqual(NOT_AFTER)
    expect(cert.basicConstraints).toEqual({ cA: false, pathLenConstraint: undefined })
    expect(cert.keyUsage).toEqual(['digitalSignature'])
    expect(cert.extendedKeyUsage).toEqual(['1.3.6.1.5.5.7.3.2'])
    expect(cert.policies).toEqual([
      { oid: '1.2.3.4', cpsUris: ['https://ca.example.com/cps'], userNotices: [] },
      { oid: '1.2.3.5', cpsUris: [], userNotices: [] },
    ])
    expect(telephoneNumbers(cert.subjectAlternativeNames)).toEqual(['+49 30 123456'])
    expect(cert.subjectAlternativeNames.dnsNames).toEqual(['service.example.com'])
    expect(cert.authorityKeyIdentifier).toBe(parseCertificate(CA_CERTIFICATE_PEM).subjectKeyIdentifier)
    expect(cert.subjectKeyIdentifier).toMatch(/^[0-9a-f]{40}$/)
    expect(cert.crlDistributionPoints).toEqual(['https://ca.example.com/crl'])
    expect(cert.ocspUrls).toEqual(['https://ocsp.example.com'])
    expect(cert.caIssuersUrls).toEqual(['https://ca.example.com/ca.crt'])
    expect(cert.qcStatements).toMatchObject({ qcCompliance: true, qcTypes: ['esign'], legislationCountries: ['DE'] })
    expect(cert.extensions.find((e) => e.oid === '2.5.29.19')?.critical).toBe(true)
    expect(cert.extensions.find((e) => e.oid === '2.5.29.15')?.critical).toBe(true)

    expect(await verifyCertificateSignature(cert, CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(true)
  })

  it('creates a self-signed CA certificate', async () => {
    const pair = await globalThis.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, [
      'sign',
      'verify',
    ])
    const privateJwk = await globalThis.crypto.subtle.exportKey('jwk', pair.privateKey)
    const { d: _, ...publicJwk } = privateJwk
    const ca = await createCertificate({
      subject: [
        ['countryName', 'DE'],
        ['commonName', 'Test Root'],
      ],
      subjectPublicKey: publicJwk,
      serialNumber: '01',
      notBefore: NOT_BEFORE,
      notAfter: NOT_AFTER,
      signatureAlgorithm: 'ES384',
      basicConstraints: { cA: true, pathLenConstraint: 1 },
      hasher: digest,
      signer: await webCryptoSigner(privateJwk, 'SHA-384'),
    })
    expect(ca.issuer).toEqual(ca.subject)
    expect(ca.basicConstraints).toEqual({ cA: true, pathLenConstraint: 1 })
    expect(ca.keyUsage).toEqual(['crlSign', 'keyCertSign'])
    expect(ca.authorityKeyIdentifier).toBe(ca.subjectKeyIdentifier)
    expect(ca.publicKey.jwk?.crv).toBe('P-384')
    expect(await verifyCertificateSignature(ca, ca, webCryptoVerifier)).toBe(true)
  })

  it('supports signers returning DER encoded ECDSA signatures', async () => {
    const signer = await webCryptoSigner(CA_PRIVATE_JWK)
    const cert = await createCertificate({
      ...(await leafTemplate()),
      signer: async (tbs) => ecdsaP1363ToDer(await signer(tbs), 32),
      signatureEncoding: 'der',
    })
    expect(await verifyCertificateSignature(cert, CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(true)
  })

  it('supports a detached signing flow', async () => {
    const prepared = await prepareCertificate(await leafTemplate())
    const signature = await (await webCryptoSigner(CA_PRIVATE_JWK))(prepared.tbs)
    const cert = assembleCertificate(prepared, signature)
    expect(cert.tbsCertificate).toEqual(prepared.tbs)
    expect(await verifyCertificateSignature(cert, CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(true)
  })

  it('appends custom extensions and rejects duplicates', async () => {
    const custom = { oid: '1.2.3.4.5', critical: false, value: new Uint8Array([0x05, 0x00]) }
    const cert = await createCertificate({
      ...(await leafTemplate()),
      extensions: [custom],
      signer: await webCryptoSigner(CA_PRIVATE_JWK),
    })
    expect(cert.extensions.find((e) => e.oid === '1.2.3.4.5')).toEqual(custom)
    await expect(
      prepareCertificate({ ...(await leafTemplate()), extensions: [{ ...custom, oid: '2.5.29.19' }] })
    ).rejects.toThrow(/Duplicate extension 2.5.29.19/)
  })

  it('validates its input', async () => {
    const template = await leafTemplate()
    await expect(prepareCertificate({ ...template, subjectPublicKey: CA_PRIVATE_JWK })).rejects.toThrow(
      /must not contain private key material/
    )
    await expect(prepareCertificate({ ...template, serialNumber: '00' })).rejects.toThrow(/positive integer/)
    await expect(prepareCertificate({ ...template, serialNumber: 'ff'.repeat(21) })).rejects.toThrow(/20 octets/)
    await expect(prepareCertificate({ ...template, notAfter: NOT_BEFORE })).rejects.toThrow(/notAfter/)
    await expect(prepareCertificate({ ...template, subject: [['nickname', 'x']] })).rejects.toThrow(
      /Unknown name attribute/
    )
    await expect(prepareCertificate({ ...template, subject: [] })).rejects.toThrow(/subject must not be empty/)
    const prepared = await prepareCertificate(template)
    expect(() => assembleCertificate(prepared, new Uint8Array(10))).toThrow(/IEEE P1363/)
  })
})

describe('publicJwkToSpki', () => {
  it('matches the WebCrypto SPKI export for EC keys', async () => {
    for (const curve of ['P-256', 'P-384', 'P-521']) {
      const { publicJwk, spki } = await generateSubjectKey(curve)
      expect(publicJwkToSpki(publicJwk)).toEqual(spki)
    }
  })

  it('matches the WebCrypto SPKI export for RSA keys', async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify']
    )
    const jwk = await globalThis.crypto.subtle.exportKey('jwk', pair.publicKey)
    const spki = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', pair.publicKey))
    expect(publicJwkToSpki(jwk)).toEqual(spki)
  })
})
