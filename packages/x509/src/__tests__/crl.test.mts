import { describe, expect, it } from 'vitest'
import {
  assembleCrl,
  type Certificate,
  type Crl,
  type CrlTemplate,
  checkRevocation,
  createCertificate,
  createCrl,
  getRevocationStatus,
  parseCertificate,
  parseCrl,
  prepareCrl,
  toDer,
  verifyCrlSignature,
  X509Exception,
} from '../index'
import { generateSubjectKey, webCryptoSigner, webCryptoVerifier } from './crypto.mjs'
import { CA_CERTIFICATE_PEM, CA_PRIVATE_JWK, OPENSSL_CRL_PEM, OPENSSL_LEAF_CERTIFICATE_PEM } from './fixtures.mjs'

const NOW = new Date('2026-10-10T00:00:00Z')

async function issueLeaf(serialNumber: string, crlDistributionPoints = ['https://ca.example.com/crl']) {
  return createCertificate({
    subject: [['commonName', `Leaf ${serialNumber}`]],
    subjectPublicKey: (await generateSubjectKey()).publicJwk,
    issuerCertificate: CA_CERTIFICATE_PEM,
    serialNumber,
    notBefore: new Date('2026-09-01T00:00:00Z'),
    notAfter: new Date('2027-09-01T00:00:00Z'),
    signatureAlgorithm: 'ES256',
    crlDistributionPoints,
    signer: await webCryptoSigner(CA_PRIVATE_JWK),
  })
}

function crlTemplate(overrides: Partial<CrlTemplate> = {}): CrlTemplate {
  return {
    issuerCertificate: CA_CERTIFICATE_PEM,
    thisUpdate: new Date('2026-10-01T00:00:00Z'),
    nextUpdate: new Date('2026-10-31T00:00:00Z'),
    crlNumber: 1,
    signatureAlgorithm: 'ES256',
    ...overrides,
  }
}

async function signedCrl(overrides: Partial<CrlTemplate> = {}): Promise<Crl> {
  return createCrl({ ...crlTemplate(overrides), signer: await webCryptoSigner(CA_PRIVATE_JWK) })
}

describe('parseCrl', () => {
  const crl = parseCrl(OPENSSL_CRL_PEM)

  it('parses an OpenSSL generated CRL', () => {
    expect(crl.version).toBe(2)
    expect(crl.issuer).toEqual(parseCertificate(CA_CERTIFICATE_PEM).subject)
    expect(crl.thisUpdate.toISOString()).toBe('2026-09-28T20:26:27.000Z')
    expect(crl.nextUpdate?.toISOString()).toBe('2026-10-28T20:26:27.000Z')
    expect(crl.signatureAlgorithmName).toBe('ES256')
    expect(crl.crlNumber).toBe(BigInt(4096))
    expect(crl.deltaCrlIndicator).toBeUndefined()
    expect(crl.authorityKeyIdentifier).toBe(parseCertificate(CA_CERTIFICATE_PEM).subjectKeyIdentifier)
    expect(crl.issuingDistributionPoint).toEqual({
      distributionPointUris: ['https://ca.example.com/crl'],
      onlyContainsUserCerts: true,
      onlyContainsCACerts: false,
      onlyContainsAttributeCerts: false,
      indirectCRL: false,
      onlySomeReasons: undefined,
    })
    expect(crl.revokedCertificates).toEqual([
      {
        serialNumber: '0badc0de',
        revocationDate: new Date('2026-09-28T20:26:27.000Z'),
        reason: 'keyCompromise',
        invalidityDate: new Date('2026-09-15T12:00:00.000Z'),
        certificateIssuer: undefined,
        extensions: expect.any(Array),
      },
    ])
  })

  it('accepts PEM, base64 DER and DER bytes', () => {
    const der = toDer(OPENSSL_CRL_PEM, 'X509 CRL')
    expect(parseCrl(der).crlNumber).toBe(BigInt(4096))
    expect(crl.pem.replace(/\s/g, '')).toBe(OPENSSL_CRL_PEM.replace(/\s/g, ''))
  })

  it('rejects malformed input', () => {
    expect(() => parseCrl(OPENSSL_LEAF_CERTIFICATE_PEM)).toThrow(/No PEM block with label "X509 CRL"/)
    expect(() => parseCrl(toDer(OPENSSL_LEAF_CERTIFICATE_PEM))).toThrow(X509Exception)
  })
})

describe('verifyCrlSignature', () => {
  it('verifies the CRL against its issuer', async () => {
    expect(await verifyCrlSignature(parseCrl(OPENSSL_CRL_PEM), CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(true)
  })

  it('rejects another issuer and tampered CRLs', async () => {
    const crl = parseCrl(OPENSSL_CRL_PEM)
    expect(await verifyCrlSignature(crl, OPENSSL_LEAF_CERTIFICATE_PEM, webCryptoVerifier)).toBe(false)
    const tbsCertList = crl.tbsCertList.slice()
    tbsCertList[tbsCertList.length - 1] ^= 0xff
    expect(await verifyCrlSignature({ ...crl, tbsCertList }, CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(false)
  })
})

describe('getRevocationStatus', () => {
  const crl = parseCrl(OPENSSL_CRL_PEM)
  const revokedLeaf = parseCertificate(OPENSSL_LEAF_CERTIFICATE_PEM)

  it('reports revoked certificates', () => {
    expect(getRevocationStatus(revokedLeaf, crl, { now: NOW })).toEqual({
      status: 'revoked',
      revocationDate: new Date('2026-09-28T20:26:27.000Z'),
      reason: 'keyCompromise',
      invalidityDate: new Date('2026-09-15T12:00:00.000Z'),
    })
  })

  it('reports certificates that are not listed as good', async () => {
    expect(getRevocationStatus(await issueLeaf('1234'), crl, { now: NOW })).toEqual({ status: 'good' })
  })

  it('matches serial numbers regardless of leading zero octets', async () => {
    const leaf = await issueLeaf('0badc0de')
    expect(leaf.serialNumber).toBe('0badc0de')
    const withHighBit = await issueLeaf('8badc0de')
    expect(withHighBit.serialNumber).toBe('008badc0de')
    const crlWithHighBit = await signedCrl({
      revokedCertificates: [{ serialNumber: '8badc0de', revocationDate: new Date('2026-10-02T00:00:00Z') }],
    })
    expect(getRevocationStatus(withHighBit, crlWithHighBit, { now: NOW }).status).toBe('revoked')
  })

  it('checks the CRL freshness', () => {
    expect(getRevocationStatus(revokedLeaf, crl, { now: new Date('2026-09-01T00:00:00Z') })).toMatchObject({
      status: 'unknown',
      reason: 'crl_not_yet_valid',
    })
    expect(getRevocationStatus(revokedLeaf, crl, { now: new Date('2026-11-01T00:00:00Z') })).toMatchObject({
      status: 'unknown',
      reason: 'crl_expired',
    })
    expect(getRevocationStatus(revokedLeaf, crl, { now: false }).status).toBe('revoked')
  })

  it('requires the certificate issuer to match', () => {
    const ca = parseCertificate(CA_CERTIFICATE_PEM)
    const otherIssuer: Certificate = { ...revokedLeaf, issuer: revokedLeaf.subject }
    expect(getRevocationStatus(otherIssuer, crl, { now: NOW })).toMatchObject({ reason: 'issuer_mismatch' })
    const otherKey: Certificate = { ...revokedLeaf, authorityKeyIdentifier: '00'.repeat(20) }
    expect(getRevocationStatus(otherKey, crl, { now: NOW })).toMatchObject({ reason: 'issuer_mismatch' })
    expect(ca.issuer).toEqual(crl.issuer)
  })

  it('respects the issuing distribution point scope', async () => {
    const ca = parseCertificate(CA_CERTIFICATE_PEM)
    // OpenSSL CRL only covers end-entity certificates
    expect(getRevocationStatus(ca, crl, { now: NOW })).toMatchObject({ reason: 'out_of_scope' })
    // Certificates pointing to another distribution point are not covered
    const otherDp = await issueLeaf('4321', ['https://ca.example.com/other.crl'])
    expect(getRevocationStatus(otherDp, crl, { now: NOW })).toMatchObject({ reason: 'out_of_scope' })
    const caOnly = await signedCrl({ issuingDistributionPoint: { onlyContainsCACerts: true } })
    expect(getRevocationStatus(revokedLeaf, caOnly, { now: NOW })).toMatchObject({ reason: 'out_of_scope' })
  })

  it('does not decide on delta CRLs or unknown critical extensions', async () => {
    const delta = await signedCrl({
      extensions: [{ oid: '2.5.29.27', critical: true, value: new Uint8Array([0x02, 0x01, 0x01]) }],
    })
    expect(delta.deltaCrlIndicator).toBe(BigInt(1))
    expect(getRevocationStatus(revokedLeaf, delta, { now: NOW })).toMatchObject({ reason: 'delta_crl' })

    const unknownCritical = await signedCrl({
      extensions: [{ oid: '1.2.3.4', critical: true, value: new Uint8Array([0x05, 0x00]) }],
    })
    expect(getRevocationStatus(revokedLeaf, unknownCritical, { now: NOW })).toMatchObject({
      reason: 'unsupported_critical_extension',
    })
  })

  it('treats removeFromCRL entries as not revoked', async () => {
    const removed = await signedCrl({
      revokedCertificates: [
        { serialNumber: '0badc0de', revocationDate: new Date('2026-10-02T00:00:00Z'), reason: 'removeFromCRL' },
      ],
    })
    expect(getRevocationStatus(revokedLeaf, removed, { now: NOW })).toEqual({ status: 'good' })
  })
})

describe('checkRevocation', () => {
  it('verifies the signature before looking up the status', async () => {
    const certificate = parseCertificate(OPENSSL_LEAF_CERTIFICATE_PEM)
    const crl = parseCrl(OPENSSL_CRL_PEM)
    const options = {
      certificate,
      crl,
      crlIssuerCertificate: CA_CERTIFICATE_PEM,
      verifier: webCryptoVerifier,
      now: NOW,
    }
    expect(await checkRevocation(options)).toMatchObject({ status: 'revoked', reason: 'keyCompromise' })
    expect(await checkRevocation({ ...options, verifier: () => false })).toMatchObject({
      status: 'unknown',
      reason: 'invalid_signature',
    })
  })
})

describe('createCrl', () => {
  it('creates a CRL that round-trips through the parser', async () => {
    const crlNumber = BigInt(2) ** BigInt(70)
    const crl = await signedCrl({
      crlNumber,
      revokedCertificates: [
        {
          serialNumber: '0badc0de',
          revocationDate: new Date('2026-10-02T00:00:00Z'),
          reason: 'keyCompromise',
          invalidityDate: new Date('2026-09-30T00:00:00Z'),
        },
        { serialNumber: '1234', revocationDate: new Date('2026-10-03T00:00:00Z') },
        { serialNumber: '5678', revocationDate: new Date('2026-10-04T00:00:00Z'), reason: 'certificateHold' },
      ],
      issuingDistributionPoint: { distributionPointUris: ['https://ca.example.com/crl'], onlyContainsUserCerts: true },
    })

    expect(crl.version).toBe(2)
    expect(crl.crlNumber).toBe(crlNumber)
    expect(crl.thisUpdate).toEqual(new Date('2026-10-01T00:00:00Z'))
    expect(crl.nextUpdate).toEqual(new Date('2026-10-31T00:00:00Z'))
    expect(crl.authorityKeyIdentifier).toBe(parseCertificate(CA_CERTIFICATE_PEM).subjectKeyIdentifier)
    expect(crl.issuingDistributionPoint).toMatchObject({
      distributionPointUris: ['https://ca.example.com/crl'],
      onlyContainsUserCerts: true,
    })
    expect(crl.extensions.find((e) => e.oid === '2.5.29.28')?.critical).toBe(true)
    expect(
      crl.revokedCertificates.map(({ serialNumber, reason, invalidityDate }) => ({
        serialNumber,
        reason,
        invalidityDate,
      }))
    ).toEqual([
      { serialNumber: '0badc0de', reason: 'keyCompromise', invalidityDate: new Date('2026-09-30T00:00:00Z') },
      { serialNumber: '1234', reason: undefined, invalidityDate: undefined },
      { serialNumber: '5678', reason: 'certificateHold', invalidityDate: undefined },
    ])

    expect(await verifyCrlSignature(crl, CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(true)
    expect(getRevocationStatus(parseCertificate(OPENSSL_LEAF_CERTIFICATE_PEM), crl, { now: NOW })).toMatchObject({
      status: 'revoked',
      reason: 'keyCompromise',
    })
  })

  it('creates an empty CRL', async () => {
    const crl = await signedCrl()
    expect(crl.revokedCertificates).toEqual([])
    expect(getRevocationStatus(parseCertificate(OPENSSL_LEAF_CERTIFICATE_PEM), crl, { now: NOW })).toEqual({
      status: 'good',
    })
  })

  it('supports a detached signing flow', async () => {
    const prepared = prepareCrl(crlTemplate())
    const crl = assembleCrl(prepared, await (await webCryptoSigner(CA_PRIVATE_JWK))(prepared.tbs))
    expect(crl.tbsCertList).toEqual(prepared.tbs)
    expect(await verifyCrlSignature(crl, CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(true)
  })

  it('validates its input', () => {
    expect(() => prepareCrl(crlTemplate({ nextUpdate: new Date('2026-09-01T00:00:00Z') }))).toThrow(/nextUpdate/)
    expect(() => prepareCrl(crlTemplate({ crlNumber: -1 }))).toThrow(/must not be negative/)
    expect(() => prepareCrl(crlTemplate({ crlNumber: BigInt(2) ** BigInt(160) }))).toThrow(/20 octets/)
  })

  // More entries than the asn1js default node limit (about 1 200 CRL entries) allows
  it('handles large CRLs', { timeout: 30_000 }, async () => {
    const revokedCertificates = Array.from({ length: 3_000 }, (_, i) => ({
      serialNumber: (i + 1).toString(16).padStart(8, '0'),
      revocationDate: new Date('2026-10-02T00:00:00Z'),
      reason: 'cessationOfOperation' as const,
    }))
    const crl = await signedCrl({ revokedCertificates })
    const parsed = parseCrl(crl.der)
    expect(parsed.revokedCertificates).toHaveLength(3_000)
    expect(getRevocationStatus(await issueLeaf('00000bb8'), parsed, { now: NOW }).status).toBe('revoked')
    expect(getRevocationStatus(await issueLeaf('00000bb9'), parsed, { now: NOW }).status).toBe('good')
    expect(() => parseCrl(crl.der, { maxEntries: 1_000 })).toThrow(X509Exception)
  })
})
