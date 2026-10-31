import { ACCESS_CERTIFICATE_VALIDATION_CODES } from '@owf/eudi-access-certificate'
import { WRP_ENTITLEMENTS, WRPRC_VALIDATION_CODES, wrprc } from '@owf/eudi-registration-certificate'
import { base64, base64urlEncode, decodeJwt } from '@owf/identity-common'
import { createHeaderAndPayload, STATUS_LIST_VALIDATION_CODES, StatusList } from '@owf/token-status-list'
import { describe, expect, it } from 'vitest'
import {
  CA_CERTIFICATE_PEM,
  OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM,
} from '../../../eudi-access-certificate/src/__tests__/fixtures.mjs'
import { WRPACProvidersJWT } from '../../../eudi-lote/src/__tests__/fixtures.mjs'
import { SIGNED_TSL_XML, UNSIGNED_TSL_XML } from '../../../eudi-tl/src/__tests__/fixtures.mjs'
import { InspectionError, inspect } from '../index'
import { anchorOf, formatPath } from '../paths'

const pemToDer = (pem: string) => base64.decode(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''))

const fakeJws = (header: Record<string, unknown>, payload: unknown) =>
  `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(payload))}.c2ln`

describe('inspect', () => {
  it('recognises a trusted list and verifies its signature', async () => {
    const inspection = inspect(SIGNED_TSL_XML)
    expect(inspection.kind).toBe('trusted-list')
    expect(inspection.checks[0]).toBe('ETSI TS 119 612 structure')
    await expect(inspection.signatures?.[0].verify(crypto)).resolves.toMatchObject({
      status: 'valid',
      message: expect.stringContaining('This proves integrity only'),
    })
  })

  it('rejects the signature of an unsigned trusted list', async () => {
    const inspection = inspect(UNSIGNED_TSL_XML)
    expect(inspection.kind).toBe('trusted-list')
    await expect(inspection.signatures?.[0].verify(crypto)).resolves.toMatchObject({ status: 'invalid' })
  })

  it('recognises an access certificate as PEM, base64 and DER', () => {
    const der = pemToDer(OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM)
    for (const input of [OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM, base64.encode(der), der]) {
      const inspection = inspect(input)
      expect(inspection.kind).toBe('access-certificate')
      expect(inspection.title).toBe('Access certificate (ETSI TS 119 411-8)')
    }
  })

  it('reports the findings of an access certificate with paths into the parsed certificate', () => {
    const inspection = inspect(CA_CERTIFICATE_PEM)
    expect(inspection.title).toBe('X.509 certificate, checked as an access certificate')
    expect(inspection.findings).toContainEqual(
      expect.objectContaining({
        code: ACCESS_CERTIFICATE_VALIDATION_CODES.MISSING_POLICY,
        path: ['certificate', 'policies'],
      })
    )
    for (const finding of inspection.findings) {
      expect(anchorOf(inspection.value, finding.path).missing).toEqual([])
    }
  })

  it('recognises a LoTE as JWS and checks its profile', () => {
    const inspection = inspect(WRPACProvidersJWT)
    expect(inspection.kind).toBe('lote')
    expect(inspection.checks).toEqual(['ETSI TS 119 602 structure', 'EUWRPACProvidersList profile'])
    expect(inspection.value).toMatchObject({ header: expect.any(Object), payload: { LoTE: expect.any(Object) } })
  })

  it('recognises a LoTE as JSON and prefixes nothing to its finding paths', () => {
    const { payload } = decodeJwt<Record<string, unknown>, Record<string, any>>(WRPACProvidersJWT)
    payload.LoTE.ListAndSchemeInformation.StatusDeterminationApproach = 'invalid'

    const inspection = inspect(JSON.stringify(payload))
    expect(inspection.kind).toBe('lote')
    expect(inspection.findings.length).toBeGreaterThan(0)
    // the profile repeats the issue of the structure schema, which is reported once
    expect(new Set(inspection.findings.map((f) => `${f.code}|${f.path.join('.')}`)).size).toBe(
      inspection.findings.length
    )
    for (const finding of inspection.findings) {
      expect(finding.path.slice(0, 3)).toEqual(['LoTE', 'ListAndSchemeInformation', 'StatusDeterminationApproach'])
    }
  })

  it('recognises a registration certificate', () => {
    const payload = wrprc()
      .name('Example')
      .legalName('Example N.V.')
      .identifier('LEINL-529900T8BM49AURSDO55')
      .country('NL')
      .registryUri('https://registry.test/wrp')
      .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
      .issuedAt(1_700_000_000)
      .expiresAt(1_700_000_000 + 400 * 24 * 3600)
      .build()

    const inspection = inspect(fakeJws({ typ: 'rc-wrp+jwt', alg: 'ES256' }, payload))
    expect(inspection.kind).toBe('registration-certificate')
    expect(inspection.findings).toContainEqual(
      expect.objectContaining({ code: WRPRC_VALIDATION_CODES.EXP_TOO_LATE, path: ['payload', 'exp'] })
    )
    // without an access certificate, its subject is not compared
    expect(inspection.findings.map((f) => f.code)).not.toContain(
      WRPRC_VALIDATION_CODES.ACCESS_CERTIFICATE_IDENTITY_MISMATCH
    )
  })

  it('recognises a status list, counts its statuses and looks up an index', () => {
    const list = new StatusList([0, 1, 2, 0, 0, 0, 0, 0], 2)
    const { header, payload } = createHeaderAndPayload(
      list,
      { sub: 'https://example.com/statuslists/1', iat: Math.floor(Date.now() / 1000), ttl: 300 },
      { alg: 'ES256', typ: 'statuslist+jwt' }
    )

    const inspection = inspect(fakeJws(header, payload))
    expect(inspection.kind).toBe('status-list')
    // exp is missing, which is RECOMMENDED
    expect(inspection.findings.map((f) => [f.severity, f.code, f.path])).toEqual([
      ['warning', STATUS_LIST_VALIDATION_CODES.MISSING_EXPIRATION_TIME, ['payload', 'exp']],
    ])
    expect(inspection.facts).toEqual([
      ['Entries', '8 of 2 bits, padded to whole bytes'],
      ['Statuses', 'Valid (0x00): 6, Invalid (0x01): 1, Suspended (0x02): 1'],
    ])
    expect(inspection.lookup?.find('1')).toBe('Invalid (0x01)')
    expect(inspection.lookup?.find('8')).toBe('The index must be a whole number from 0 to 7')
  })

  it('rejects input it does not recognise', () => {
    expect(() => inspect('')).toThrow(InspectionError)
    expect(() => inspect('hello world!')).toThrow(InspectionError)
    expect(() => inspect('{"foo": 1}')).toThrow('not a LoTE document')
    expect(() => inspect('<html></html>')).toThrow('not a parsable ETSI TS 119 612 trusted list')
    expect(() => inspect(fakeJws({ typ: 'JWT' }, { sub: 'x' }))).toThrow('neither a registration certificate')
  })
})

describe('paths', () => {
  it('anchors a path at the deepest element that is present', () => {
    const value = { certificate: { subject: { countryName: 'NL' } }, list: [{ a: 1 }] }
    expect(anchorOf(value, ['certificate', 'subject', 'commonName'])).toEqual({
      anchor: ['certificate', 'subject'],
      missing: ['commonName'],
    })
    expect(anchorOf(value, ['list', 0, 'a'])).toEqual({ anchor: ['list', 0, 'a'], missing: [] })
    expect(anchorOf(value, ['list', 1])).toEqual({ anchor: ['list'], missing: [1] })
  })

  it('formats a path for display', () => {
    expect(formatPath([])).toBe('(document)')
    expect(formatPath(['providers', 0, 'services', 1, 'serviceStatus'])).toBe('providers[0].services[1].serviceStatus')
  })
})
