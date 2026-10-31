import { WRP_ENTITLEMENTS, WRPRC_VALIDATION_CODES, wrprc } from '@owf/eudi-registration-certificate'
import { base64urlEncode } from '@owf/identity-common'
import { createHeaderAndPayload, STATUS_LIST_VALIDATION_CODES, StatusList } from '@owf/token-status-list'
import { describe, expect, it } from 'vitest'
import {
  CA_CERTIFICATE_PEM,
  OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM,
} from '../../../eudi-access-certificate/src/__tests__/fixtures.mjs'
import {
  NATIONAL_POINTER_CERT_BASE64,
  SIGNED_TSL_XML,
  SIGNER_CERT_BASE64,
  UNSIGNED_TSL_XML,
} from '../../../eudi-tl/src/__tests__/fixtures.mjs'
import { inspectAccessCertificate } from '../access-certificate'
import { detect } from '../detect'
import { inspectRegistrationCertificate } from '../registration-certificate'
import { inspectStatusList } from '../status-list'
import { inspectTrustedList } from '../trusted-list'

const fakeJws = (header: Record<string, unknown>, payload: unknown) =>
  `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(payload))}.c2ln`

const verify = (inspection: { signatures?: { verify: (crypto: Crypto) => Promise<unknown> }[] }) =>
  inspection.signatures?.[0].verify(crypto)

describe('options of the format pages', () => {
  it('checks the signer of a trusted list against the certificates you give', async () => {
    await expect(verify(inspectTrustedList(SIGNED_TSL_XML, { signers: SIGNER_CERT_BASE64 }))).resolves.toMatchObject({
      status: 'valid',
      message: expect.stringContaining('signed with a certificate you gave'),
    })
    await expect(
      verify(inspectTrustedList(SIGNED_TSL_XML, { signers: NATIONAL_POINTER_CERT_BASE64 }))
    ).resolves.toMatchObject({ status: 'invalid', message: expect.stringContaining('not among the configured') })
  })

  it('says when the EU LOTL to check the signer against cannot be loaded', async () => {
    const inspection = inspectTrustedList(UNSIGNED_TSL_XML, { loadLotl: () => Promise.reject(new Error('offline')) })
    expect(inspection.facts).toContainEqual(['Territory', 'ES'])
    await expect(verify(inspection)).resolves.toEqual({
      status: 'unverified',
      message: 'Not verified: the EU LOTL cannot be loaded: offline',
    })
  })

  it('compares the subject of a registration certificate with the access certificate', () => {
    const registration = (identifier: string) =>
      fakeJws(
        { typ: 'rc-wrp+jwt', alg: 'ES256', iat: 1_700_000_000 },
        wrprc()
          .name('Example')
          .legalName('Example GmbH')
          .identifier(identifier)
          .country('DE')
          .registryUri('https://registry.test/wrp')
          .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
          .issuedAt(1_700_000_000)
          .build()
      )
    const codes = (identifier: string) =>
      inspectRegistrationCertificate(registration(identifier), {
        accessCertificate: OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM,
      }).findings.map((finding) => finding.code)

    // The organizationIdentifier of the access certificate fixture
    expect(codes('VATDE-123456789')).not.toContain(WRPRC_VALIDATION_CODES.ACCESS_CERTIFICATE_IDENTITY_MISMATCH)
    expect(codes('VATDE-987654321')).toContain(WRPRC_VALIDATION_CODES.ACCESS_CERTIFICATE_IDENTITY_MISMATCH)

    const inspection = inspectRegistrationCertificate(registration('VATDE-123456789'), {
      accessCertificate: OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM,
    })
    expect(inspection.facts).toContainEqual(['Access certificate subject', 'VATDE-123456789'])
    expect(inspection.value).toMatchObject({ access_certificate: { certificate: expect.any(Object) } })
  })

  it('compares sub of a status list with the uri of the reference', () => {
    const { header, payload } = createHeaderAndPayload(
      new StatusList([0, 1], 1),
      { sub: 'https://example.com/statuslists/1', iat: Math.floor(Date.now() / 1000), ttl: 300 },
      { alg: 'ES256', typ: 'statuslist+jwt' }
    )
    const jws = fakeJws(header, payload)
    expect(inspectStatusList(jws, { uri: 'https://example.com/statuslists/2' }).findings).toContainEqual(
      expect.objectContaining({ code: STATUS_LIST_VALIDATION_CODES.SUBJECT_MISMATCH, path: ['payload', 'sub'] })
    )
    expect(inspectStatusList(jws, { uri: 'https://example.com/statuslists/1' }).checks).toContain(
      'sub against the uri of the reference'
    )
  })

  it('verifies an access certificate with the certificate of its CA', async () => {
    await expect(
      verify(inspectAccessCertificate(OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM, { issuer: CA_CERTIFICATE_PEM }))
    ).resolves.toMatchObject({ status: 'valid', message: expect.stringContaining('Example WRP Access CA') })
    await expect(
      verify(
        inspectAccessCertificate(OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM, { issuer: OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM })
      )
    ).resolves.toMatchObject({ status: 'invalid' })
    await expect(verify(inspectAccessCertificate(OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM))).resolves.toMatchObject({
      status: 'unverified',
    })
  })

  it('recognises the format of a document', () => {
    expect(detect(SIGNED_TSL_XML)).toBe('trusted-list')
    expect(detect(new TextEncoder().encode(OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM))).toBe('access-certificate')
    expect(detect(fakeJws({ typ: 'statuslist+jwt' }, {}))).toBe('status-list')
  })
})
