import { VALIDATION_CODES, ValidationError, type ValidationSeverity } from '@owf/identity-common'
import { parseCertificate, verifyCertificateSignature, X509Error } from '@owf/x509'
import { describe, expect, it } from 'vitest'
import {
  type AccessCertificate,
  AccessCertificateValidationError,
  type AccessCertificateValidationResult,
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
    expect(() => parseAccessCertificate('not a certificate!')).toThrow(X509Error)
  })
})

/** The codes of the issues with the given severity */
const codes = (result: AccessCertificateValidationResult, severity: ValidationSeverity) =>
  result.issues.filter((issue) => issue.severity === severity).map((issue) => issue.code)

describe('validateAccessCertificate', () => {
  const ac = parseAccessCertificate(OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM)

  it('accepts a conforming certificate', () => {
    expect(validateAccessCertificate(ac, { now: NOW })).toEqual({ valid: true, issues: [] })
  })

  it('checks the validity period, with the common codes and the dates as context', () => {
    const issues = (now: Date) => validateAccessCertificate(ac, { now }).issues
    expect(issues(new Date('2020-01-01T00:00:00Z'))).toEqual([
      expect.objectContaining({
        severity: 'error',
        code: VALIDATION_CODES.NOT_YET_VALID,
        path: ['certificate', 'notBefore'],
        context: { validFrom: ac.certificate.notBefore },
      }),
    ])
    expect(issues(new Date('2040-01-01T00:00:00Z'))).toEqual([
      expect.objectContaining({
        severity: 'error',
        code: VALIDATION_CODES.EXPIRED,
        path: ['certificate', 'notAfter'],
        context: { expiredAt: ac.certificate.notAfter },
      }),
    ])
    expect(validateAccessCertificate(ac, { now: false }).valid).toBe(true)
  })

  it('reports certificates that do not follow the profile', () => {
    // The CA certificate is a legal person certificate without any TS 119 411-8 content
    const result = validateAccessCertificate(parseAccessCertificate(CA_CERTIFICATE_PEM), { now: NOW })
    expect(result.valid).toBe(false)
    expect(codes(result, 'error')).toEqual([
      CODES.CA_CERTIFICATE,
      CODES.MISSING_POLICY,
      CODES.MISSING_CPS_URI,
      CODES.MISSING_CONTACT,
    ])
    expect(result.issues.find((issue) => issue.code === CODES.MISSING_CONTACT)?.requirement).toBe('GEN-6.6.1-07')
    expect(codes(result, 'warning')).toEqual([CODES.MISSING_DIGITAL_SIGNATURE_KEY_USAGE])
  })

  it('reports each issue pointing at the checked certificate field', () => {
    const result = validateAccessCertificate(parseAccessCertificate(CA_CERTIFICATE_PEM), { now: NOW })
    expect(result.issues.map(({ severity, code, path }) => ({ severity, code, path }))).toEqual([
      { severity: 'error', code: CODES.CA_CERTIFICATE, path: ['certificate', 'basicConstraints', 'cA'] },
      { severity: 'warning', code: CODES.MISSING_DIGITAL_SIGNATURE_KEY_USAGE, path: ['certificate', 'keyUsage'] },
      { severity: 'error', code: CODES.MISSING_POLICY, path: ['certificate', 'policies'] },
      { severity: 'error', code: CODES.MISSING_CPS_URI, path: ['certificate', 'policies'] },
      { severity: 'error', code: CODES.MISSING_CONTACT, path: ['certificate', 'subjectAlternativeNames'] },
    ])
  })

  it('accepts TSP allocated policy OIDs when configured', () => {
    const withoutPolicy: AccessCertificate = {
      ...ac,
      policies: [],
      qualified: false,
      certificate: { ...ac.certificate, policies: [] },
    }
    expect(codes(validateAccessCertificate(withoutPolicy, { now: NOW }), 'error')).toEqual([
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
    const identifierCodes = (organizationIdentifier: string) =>
      codes(validateAccessCertificate(withSubject(ac, { organizationIdentifier }), { now: NOW }), 'error')
    expect(identifierCodes('123456789')).toEqual([CODES.INVALID_ORGANIZATION_IDENTIFIER])
    expect(identifierCodes('VATGR-123456789')).toEqual([CODES.INVALID_GREECE_COUNTRY_CODE])
    expect(identifierCodes('VATEL-123456789')).toEqual([])
  })

  it('checks natural person names', () => {
    const natural: AccessCertificate = { ...ac, subjectType: 'natural', qualified: false }
    const result = validateAccessCertificate(natural, { now: NOW })
    expect(codes(result, 'error')).toEqual([CODES.MISSING_NATURAL_PERSON_NAME])
    expect(codes(result, 'warning')).toEqual([CODES.MISSING_SERIAL_NUMBER])
    const named = withSubject(natural, { givenName: 'Erika', serialNumber: 'PNODE-1234' })
    expect(validateAccessCertificate(named, { now: NOW })).toEqual({ valid: true, issues: [] })
  })

  it('checks QC statements of qualified certificates', () => {
    const result = validateAccessCertificate(
      { ...ac, certificate: { ...ac.certificate, qcStatements: undefined } },
      { now: NOW }
    )
    expect(codes(result, 'error')).toEqual([CODES.MISSING_QC_COMPLIANCE])
    expect(codes(result, 'warning')).toEqual([CODES.QC_TYPE_MISMATCH])
  })

  it('throws from parseAndValidateAccessCertificate', () => {
    expect(() => parseAndValidateAccessCertificate(CA_CERTIFICATE_PEM, { now: NOW })).toThrow(
      /Invalid access certificate/
    )
    const error = (() => {
      try {
        parseAndValidateAccessCertificate(CA_CERTIFICATE_PEM, { now: NOW })
      } catch (error) {
        return error
      }
    })()
    expect(error).toBeInstanceOf(AccessCertificateValidationError)
    expect(error).toBeInstanceOf(ValidationError)
    expect((error as AccessCertificateValidationError).issues).toEqual(
      validateAccessCertificate(parseAccessCertificate(CA_CERTIFICATE_PEM), { now: NOW }).issues
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
