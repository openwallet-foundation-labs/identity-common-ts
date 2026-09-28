import { parseCertificate, verifyCertificateSignature, X509Exception } from '@owf/x509'
import { describe, expect, it } from 'vitest'
import {
  type AccessCertificate,
  ACCESS_CERTIFICATE_VALIDATION_CODES as CODES,
  getAccessCertificateSubjectIdentifier,
  parseAccessCertificate,
  parseAndValidateAccessCertificate,
  parseSemanticIdentifier,
  toAccessCertificate,
  validateAccessCertificate,
} from '../index'
import { webCryptoVerifier } from './crypto.mjs'
import { CA_CERTIFICATE_PEM, OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM } from './fixtures.mjs'

const NOW = new Date('2030-01-01T00:00:00Z')

function withSubject(ac: AccessCertificate, subject: Partial<AccessCertificate['certificate']['subject']>) {
  return { ...ac, certificate: { ...ac.certificate, subject: { ...ac.certificate.subject, ...subject } } }
}

describe('parseAccessCertificate', () => {
  const ac = parseAccessCertificate(OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM)

  it('recognises the TS 119 411-8 policy', () => {
    expect(ac.policies).toEqual(['QCP-l-eudiwrp'])
    expect(ac.subjectType).toBe('legal')
    expect(ac.qualified).toBe(true)
    expect(ac.certificate.policies[0].cpsUris).toEqual(['https://ca.example.com/cps'])
  })

  it('extracts the contact information from the SAN', () => {
    expect(ac.contact).toEqual({
      uris: ['https://shop.example.com/support'],
      emails: ['support@shop.example.com'],
      phoneNumbers: ['+4930123456'],
    })
  })

  it('parses the semantic identifier', () => {
    expect(ac.subjectIdentifier).toEqual({
      value: 'VATDE-123456789',
      type: 'VAT',
      countryCode: 'DE',
      subdivision: undefined,
      identifier: '123456789',
    })
    expect(getAccessCertificateSubjectIdentifier(ac)).toBe('VATDE-123456789')
  })

  it('exposes the underlying X.509 certificate', async () => {
    expect(ac.certificate.subject.commonName).toBe('Example Shop')
    expect(ac.certificate.qcStatements?.qcTypes).toEqual(['eseal'])
    expect(toAccessCertificate(parseCertificate(OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM))).toEqual(ac)
    expect(await verifyCertificateSignature(ac.certificate, CA_CERTIFICATE_PEM, webCryptoVerifier)).toBe(true)
  })

  it('derives the subject type from the subject without a TS 119 411-8 policy', () => {
    const ca = parseAccessCertificate(CA_CERTIFICATE_PEM)
    expect(ca.policies).toEqual([])
    expect(ca.subjectType).toBe('legal')
    expect(ca.qualified).toBe(false)
  })

  it('rejects malformed input', () => {
    expect(() => parseAccessCertificate('not a certificate!')).toThrow(X509Exception)
  })
})

describe('validateAccessCertificate', () => {
  const ac = parseAccessCertificate(OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM)

  it('accepts a conforming certificate', () => {
    expect(validateAccessCertificate(ac, { now: NOW })).toEqual({ valid: true, errors: [], warnings: [] })
  })

  it('checks the validity period', () => {
    const codes = (now: Date) => validateAccessCertificate(ac, { now }).errors.map((e) => e.code)
    expect(codes(new Date('2020-01-01T00:00:00Z'))).toEqual([CODES.NOT_YET_VALID])
    expect(codes(new Date('2040-01-01T00:00:00Z'))).toEqual([CODES.EXPIRED])
    expect(validateAccessCertificate(ac, { now: false }).valid).toBe(true)
  })

  it('reports certificates that do not follow the profile', () => {
    // The CA certificate is a legal person certificate without any TS 119 411-8 content
    const result = validateAccessCertificate(parseAccessCertificate(CA_CERTIFICATE_PEM), { now: NOW })
    expect(result.valid).toBe(false)
    expect(result.errors.map((e) => e.code)).toEqual([
      CODES.CA_CERTIFICATE,
      CODES.MISSING_POLICY,
      CODES.MISSING_CPS_URI,
      CODES.MISSING_CONTACT,
    ])
    expect(result.errors.find((e) => e.code === CODES.MISSING_CONTACT)?.requirement).toBe('GEN-6.6.1-07')
    expect(result.warnings.map((e) => e.code)).toEqual([CODES.MISSING_DIGITAL_SIGNATURE_KEY_USAGE])
  })

  it('accepts TSP allocated policy OIDs when configured', () => {
    const withoutPolicy: AccessCertificate = {
      ...ac,
      policies: [],
      qualified: false,
      certificate: { ...ac.certificate, policies: [] },
    }
    expect(validateAccessCertificate(withoutPolicy, { now: NOW }).errors.map((e) => e.code)).toEqual([
      CODES.MISSING_POLICY,
      CODES.MISSING_CPS_URI,
    ])
    const custom: AccessCertificate = {
      ...withoutPolicy,
      certificate: {
        ...ac.certificate,
        policies: [{ oid: '1.2.3.4', cpsUris: ['https://ca.example.com/cps'], userNotices: [] }],
      },
    }
    expect(validateAccessCertificate(custom, { now: NOW, acceptedPolicyOids: ['1.2.3.4'] }).valid).toBe(true)
  })

  it('checks the organizationIdentifier encoding', () => {
    const codes = (organizationIdentifier: string) =>
      validateAccessCertificate(withSubject(ac, { organizationIdentifier }), { now: NOW }).errors.map((e) => e.code)
    expect(codes('123456789')).toEqual([CODES.INVALID_ORGANIZATION_IDENTIFIER])
    expect(codes('VATGR-123456789')).toEqual([CODES.INVALID_GREECE_COUNTRY_CODE])
    expect(codes('VATEL-123456789')).toEqual([])
  })

  it('checks natural person names', () => {
    const natural: AccessCertificate = { ...ac, subjectType: 'natural', qualified: false }
    const result = validateAccessCertificate(natural, { now: NOW })
    expect(result.errors.map((e) => e.code)).toEqual([CODES.MISSING_NATURAL_PERSON_NAME])
    expect(result.warnings.map((e) => e.code)).toEqual([CODES.MISSING_SERIAL_NUMBER])
    const named = withSubject(natural, { givenName: 'Erika', serialNumber: 'PNODE-1234' })
    expect(validateAccessCertificate(named, { now: NOW })).toEqual({ valid: true, errors: [], warnings: [] })
  })

  it('checks QC statements of qualified certificates', () => {
    const result = validateAccessCertificate(
      { ...ac, certificate: { ...ac.certificate, qcStatements: undefined } },
      { now: NOW }
    )
    expect(result.errors.map((e) => e.code)).toEqual([CODES.MISSING_QC_COMPLIANCE])
    expect(result.warnings.map((e) => e.code)).toEqual([CODES.QC_TYPE_MISMATCH])
  })

  it('throws from parseAndValidateAccessCertificate', () => {
    expect(() => parseAndValidateAccessCertificate(CA_CERTIFICATE_PEM, { now: NOW })).toThrow(
      /Invalid access certificate/
    )
    expect(parseAndValidateAccessCertificate(OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM, { now: NOW }).subjectType).toBe(
      'legal'
    )
  })
})

describe('parseSemanticIdentifier', () => {
  it.each([
    ['VATBE-0876866054', { type: 'VAT', countryCode: 'BE', identifier: '0876866054' }],
    ['LEIXG-529900T8BM49AURSDO55', { type: 'LEI', countryCode: 'XG', identifier: '529900T8BM49AURSDO55' }],
    ['NTRDE+BY-HRB12345', { type: 'NTR', countryCode: 'DE', subdivision: 'BY', identifier: 'HRB12345' }],
    ['PNOEE-38001085718', { type: 'PNO', countryCode: 'EE', identifier: '38001085718' }],
    ['CF:IT-ABCDEF', { type: 'CF:', countryCode: 'IT', identifier: 'ABCDEF' }],
  ])('parses %s', (value, expected) => {
    expect(parseSemanticIdentifier(value)).toMatchObject({ value, ...expected })
  })

  it.each(['VAT-123', 'vatde-123', 'VATDE123', 'VATDE-'])('rejects %s', (value) => {
    expect(parseSemanticIdentifier(value)).toBeUndefined()
  })
})
