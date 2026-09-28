import { digest } from '@owf/crypto'
import {
  createCrl,
  ecdsaP1363ToDer,
  getRevocationStatus,
  parseCertificate,
  verifyCertificateSignature,
} from '@owf/x509'
import { describe, expect, it } from 'vitest'
import {
  assembleAccessCertificate,
  type CreateAccessCertificateOptions,
  createAccessCertificate,
  type LegalPersonAccessCertificateOptions,
  prepareAccessCertificate,
  validateAccessCertificate,
} from '../index'
import { generateSubjectKey, webCryptoSigner, webCryptoVerifier } from './crypto.mjs'
import { CA_CERTIFICATE_PEM, CA_PRIVATE_JWK } from './fixtures.mjs'

const NOT_BEFORE = new Date('2026-10-01T00:00:00Z')
const NOT_AFTER = new Date('2027-10-01T00:00:00Z')
const NOW = new Date('2027-01-01T00:00:00Z')

async function baseOptions() {
  const { publicJwk } = await generateSubjectKey()
  return {
    cpsUri: 'https://ca.example.com/cps',
    contact: {
      uris: ['https://shop.example.com/support'],
      emails: ['support@shop.example.com'],
      phoneNumbers: ['+4930123456'],
    },
    dnsNames: ['shop.example.com'],
    subjectPublicKey: publicJwk,
    issuerCertificate: CA_CERTIFICATE_PEM,
    serialNumber: 'f00dcafe',
    notBefore: NOT_BEFORE,
    notAfter: NOT_AFTER,
    signatureAlgorithm: 'ES256' as const,
    signer: await webCryptoSigner(CA_PRIVATE_JWK),
  }
}

async function legalPersonOptions(): Promise<LegalPersonAccessCertificateOptions & CreateAccessCertificateOptions> {
  return {
    ...(await baseOptions()),
    policy: 'NCP-l-eudiwrp',
    subject: {
      commonName: 'Example Shop',
      organizationName: 'Example Relying Party GmbH',
      organizationIdentifier: 'LEIXG-529900T8BM49AURSDO55',
      countryName: 'DE',
      organizationalUnitNames: ['Online Shop'],
    },
  }
}

describe('createAccessCertificate', () => {
  it('creates a legal person access certificate that round-trips through the parser', async () => {
    const options = await legalPersonOptions()
    const ac = await createAccessCertificate({
      ...options,
      crlDistributionPoints: ['https://ca.example.com/crl'],
      ocspUrls: ['https://ocsp.example.com'],
      hasher: digest,
    })
    const cert = ac.certificate

    expect(ac.policies).toEqual(['NCP-l-eudiwrp'])
    expect(ac.subjectType).toBe('legal')
    expect(ac.qualified).toBe(false)
    expect(ac.contact).toEqual(options.contact)
    expect(ac.subjectIdentifier).toMatchObject({ type: 'LEI', countryCode: 'XG' })

    expect(cert.policies).toEqual([
      { oid: '0.4.0.194118.1.2', cpsUris: ['https://ca.example.com/cps'], userNotices: [] },
    ])
    expect(cert.qcStatements).toBeUndefined()
    expect(cert.subject.rfc4514).toBe(
      'CN=Example Shop,organizationIdentifier=LEIXG-529900T8BM49AURSDO55,OU=Online Shop,O=Example Relying Party GmbH,C=DE'
    )
    expect(cert.issuer).toEqual(parseCertificate(CA_CERTIFICATE_PEM).subject)
    expect(cert.subjectAlternativeNames.dnsNames).toEqual(['shop.example.com'])
    expect(cert.basicConstraints).toEqual({ cA: false, pathLenConstraint: undefined })
    expect(cert.keyUsage).toEqual(['digitalSignature'])
    expect(cert.subjectKeyIdentifier).toMatch(/^[0-9a-f]{40}$/)
    expect(cert.crlDistributionPoints).toEqual(['https://ca.example.com/crl'])
    expect(cert.ocspUrls).toEqual(['https://ocsp.example.com'])

    expect(validateAccessCertificate(ac, { now: NOW })).toEqual({ valid: true, errors: [], warnings: [] })
    expect(await verifyCertificateSignature(cert, CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(true)
  })

  it('adds QC statements for qualified policies', async () => {
    const ac = await createAccessCertificate({
      ...(await legalPersonOptions()),
      policy: 'QCP-l-eudiwrp',
      additionalPolicyOids: ['1.2.3.4'],
      qcStatements: {
        qcSSCD: true,
        pds: [{ url: 'https://ca.example.com/pds', language: 'en' }],
        legislationCountries: ['DE'],
      },
    })
    expect(ac.qualified).toBe(true)
    expect(ac.certificate.policies.map((p) => p.oid)).toEqual(['0.4.0.194118.1.4', '1.2.3.4'])
    expect(ac.certificate.qcStatements).toEqual({
      statementIds: ['0.4.0.1862.1.1', '0.4.0.1862.1.4', '0.4.0.1862.1.6', '0.4.0.1862.1.5', '0.4.0.1862.1.7'],
      qcCompliance: true,
      qcSSCD: true,
      qcTypes: ['eseal'],
      pds: [{ url: 'https://ca.example.com/pds', language: 'en' }],
      legislationCountries: ['DE'],
    })
    expect(validateAccessCertificate(ac, { now: NOW }).valid).toBe(true)
  })

  it('creates a natural person access certificate', async () => {
    const { spki } = await generateSubjectKey()
    const ac = await createAccessCertificate({
      ...(await baseOptions()),
      policy: 'QCP-n-eudiwrp',
      subject: {
        commonName: 'Erika Mustermann',
        givenName: 'Erika',
        surname: 'Mustermann',
        serialNumber: 'IDCDE-T22000129',
        countryName: 'DE',
      },
      contact: { emails: ['erika@example.com'] },
      subjectPublicKey: spki,
    })
    expect(ac.subjectType).toBe('natural')
    expect(ac.policies).toEqual(['QCP-n-eudiwrp'])
    expect(ac.certificate.qcStatements?.qcTypes).toEqual(['esign'])
    expect(ac.subjectIdentifier).toMatchObject({ type: 'IDC', countryCode: 'DE', identifier: 'T22000129' })
    expect(ac.certificate.subject.rfc4514).toBe(
      'CN=Erika Mustermann,SERIALNUMBER=IDCDE-T22000129,SN=Mustermann,GN=Erika,C=DE'
    )
    expect(validateAccessCertificate(ac, { now: NOW })).toEqual({ valid: true, errors: [], warnings: [] })
  })

  it('supports signers that return DER encoded ECDSA signatures', async () => {
    const options = await legalPersonOptions()
    const ac = await createAccessCertificate({
      ...options,
      signer: async (tbs) => ecdsaP1363ToDer(await options.signer(tbs), 32),
      signatureEncoding: 'der',
    })
    expect(await verifyCertificateSignature(ac.certificate, CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(true)
  })

  it('supports a detached signing flow', async () => {
    const { signer, ...options } = await legalPersonOptions()
    const prepared = await prepareAccessCertificate(options)
    expect(prepared.signatureAlgorithm).toBe('ES256')
    const ac = assembleAccessCertificate(prepared, await signer(prepared.tbs))
    expect(ac.certificate.tbsCertificate).toEqual(prepared.tbs)
    expect(await verifyCertificateSignature(ac.certificate, CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(true)
  })

  it('works with CRLs from @owf/x509', async () => {
    const ac = await createAccessCertificate({
      ...(await legalPersonOptions()),
      crlDistributionPoints: ['https://ca.example.com/crl'],
    })
    const crl = await createCrl({
      issuerCertificate: CA_CERTIFICATE_PEM,
      thisUpdate: NOW,
      nextUpdate: new Date('2027-02-01T00:00:00Z'),
      crlNumber: 7,
      signatureAlgorithm: 'ES256',
      revokedCertificates: [{ serialNumber: 'f00dcafe', revocationDate: NOW, reason: 'privilegeWithdrawn' }],
      signer: await webCryptoSigner(CA_PRIVATE_JWK),
    })
    // REV-6.3.9-04: revoked after the registration of the wallet-relying party was cancelled
    expect(getRevocationStatus(ac.certificate, crl, { now: NOW })).toMatchObject({
      status: 'revoked',
      reason: 'privilegeWithdrawn',
    })
  })

  describe('input checks', () => {
    it('never accepts private key material for the subject', async () => {
      const options = await legalPersonOptions()
      await expect(createAccessCertificate({ ...options, subjectPublicKey: CA_PRIVATE_JWK })).rejects.toThrow(
        /must not contain private key material/
      )
    })

    it('requires contact information (GEN-6.6.1-07)', async () => {
      const options = await legalPersonOptions()
      await expect(createAccessCertificate({ ...options, contact: {} })).rejects.toThrow(/GEN-6.6.1-07/)
    })

    it('requires a CPS URI (GEN-6.6.1-06)', async () => {
      const options = await legalPersonOptions()
      await expect(createAccessCertificate({ ...options, cpsUri: '' })).rejects.toThrow(/GEN-6.6.1-06/)
    })

    it('requires a valid organizationIdentifier (GEN-6.6.1-05)', async () => {
      const options = await legalPersonOptions()
      await expect(
        createAccessCertificate({ ...options, subject: { ...options.subject, organizationIdentifier: 'HRB12345' } })
      ).rejects.toThrow(/GEN-6.6.1-05/)
      await expect(
        createAccessCertificate({ ...options, subject: { ...options.subject, organizationIdentifier: 'VATGR-123' } })
      ).rejects.toThrow(/"EL" for Greece/)
    })

    it('requires an ISO 3166-1 country code', async () => {
      const options = await legalPersonOptions()
      await expect(
        createAccessCertificate({ ...options, subject: { ...options.subject, countryName: 'Germany' } })
      ).rejects.toThrow(/ISO 3166-1/)
    })
  })
})
