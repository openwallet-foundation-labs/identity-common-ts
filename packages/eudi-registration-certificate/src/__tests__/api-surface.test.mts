/**
 * Tests for API surface that the conformance suite does not exercise: error paths,
 * assertion helpers, identifier prefix mapping, and the remaining builder setters.
 */

import { ES256 } from '@owf/crypto'
import { base64urlEncode } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import {
  assertValidWRPRC,
  createServiceProviderWRPRC,
  credential,
  decodeWRPRC,
  getIdentifierPrefix,
  IDENTIFIER_TYPES,
  parseWRPRC,
  signWRPRC,
  validateWRPRCPayload,
  WRP_ENTITLEMENTS,
  WRPRC_VALIDATION_CODES,
  WRPRCException,
  wrprc,
} from '../index'

const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIIBczCCARmgAwIBAgIUZt2jkmAgIIiw/wpvJU/4yL7ek/YwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yNjAzMTYxODEwMTJaFw0zNjAzMTMxODEwMTJa
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASa6ViW
voU/uOZiBHqFWLE/s+3Ts2K6XT9x2S+abUz/xu48DnP8eL89DQRS8TIUewZbW+H6
GBuyFJjG/mSuqJf+o1MwUTAdBgNVHQ4EFgQUFDKBWF8aGWeDTQHphAhWXs9/J1Aw
HwYDVR0jBBgwFoAUFDKBWF8aGWeDTQHphAhWXs9/J1AwDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNIADBFAiEAibvAwfagitnTA7zKxcl8kuUaU+oBLClK8YXg
s2WfHbwCIAQKqu6+GHkzWH8H0zMPKedvxJp34whrGoIarukWZjjp
-----END CERTIFICATE-----`

const base = () =>
  wrprc()
    .name('Example')
    .legalName('Example N.V.')
    .identifier('LEINL-529900T8BM49AURSDO55')
    .country('NL')
    .registryUri('https://registry.test/wrp')
    .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
    .issuedAt(1_700_000_000)

const signerFor = async () => ES256.getSigner((await ES256.generateKeyPair()).privateKey)

// ============================================================================
// Semantic identifiers (Tables 2 and 4)
// ============================================================================

describe('semantic identifier initial characters', () => {
  it('maps the TIN type to VAT for legal persons and TIN for natural persons', () => {
    expect(getIdentifierPrefix(IDENTIFIER_TYPES.TIN, 'legal')).toBe('VAT')
    expect(getIdentifierPrefix(IDENTIFIER_TYPES.TIN, 'natural')).toBe('TIN')
    expect(getIdentifierPrefix(IDENTIFIER_TYPES.VATIN, 'legal')).toBe('VAT')
    expect(getIdentifierPrefix(IDENTIFIER_TYPES.VATIN, 'natural')).toBe('TIN')
  })

  it('defaults to the legal person mapping and maps the remaining Table 2 types', () => {
    expect(getIdentifierPrefix(IDENTIFIER_TYPES.LEI)).toBe('LEI')
    expect(getIdentifierPrefix(IDENTIFIER_TYPES.EUID)).toBe('NTR')
    expect(getIdentifierPrefix(IDENTIFIER_TYPES.EORI)).toBe('EOR')
    expect(getIdentifierPrefix(IDENTIFIER_TYPES.EXCISE)).toBe('EXC')
  })

  it('returns undefined for a type with no mapping for that subject', () => {
    expect(getIdentifierPrefix(IDENTIFIER_TYPES.LEI, 'natural')).toBeUndefined()
    expect(getIdentifierPrefix('https://example.test/unknown')).toBeUndefined()
  })

  it('warns about initial characters outside Tables 2 and 4 without failing', () => {
    const result = validateWRPRCPayload(base().identifier('ZZZNL-12345').build())

    expect(result.valid).toBe(true)
    expect(result.warnings.map((w) => w.code)).toContain(WRPRC_VALIDATION_CODES.UNKNOWN_IDENTIFIER_PREFIX)
  })

  it('does not warn for the corrected Table 2 and Table 4 characters', () => {
    for (const sub of ['EORNL-1', 'LEIXG-1', 'NTRNL-1', 'VATNL-1', 'EXCNL-1', 'TINIT-1', 'PASDE-1', 'IDCIT-1']) {
      const result = validateWRPRCPayload(base().identifier(sub).build())
      const codes = result.warnings.map((w) => w.code)
      expect(codes, sub).not.toContain(WRPRC_VALIDATION_CODES.UNKNOWN_IDENTIFIER_PREFIX)
    }
  })

  it('rejects an identifier that does not follow the semantic format', () => {
    const result = validateWRPRCPayload(base().identifier('not-a-semantic-id').build())

    expect(result.valid).toBe(false)
    expect(result.errors.map((e) => e.code)).toContain(WRPRC_VALIDATION_CODES.INVALID_SEMANTIC_IDENTIFIER)
  })
})

// ============================================================================
// Signer error paths
// ============================================================================

describe('signWRPRC error paths', () => {
  it('requires at least one certificate', async () => {
    await expect(signWRPRC({ payload: base().build(), certificates: [], signer: await signerFor() })).rejects.toThrow(
      WRPRCException
    )
  })

  it('rejects a malformed PEM certificate', async () => {
    await expect(
      signWRPRC({ payload: base().build(), certificates: ['not a pem'], signer: await signerFor() })
    ).rejects.toThrow(/PEM/)
  })

  it('honours an explicit signing time and key id', async () => {
    const signed = await signWRPRC({
      payload: base().build(),
      certificates: [TEST_CERT],
      signer: await signerFor(),
      signingTime: 1_780_000_000,
      keyId: 'key-1',
    })

    expect(signed.header.iat).toBe(1_780_000_000)
    expect(signed.header.kid).toBe('key-1')
  })
})

// ============================================================================
// Decoding and parsing
// ============================================================================

describe('decodeWRPRC and parseWRPRC', () => {
  const compact = (header: object, payload: object) =>
    `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(payload))}.AAAA`

  it('rejects a token whose typ is not rc-wrp+jwt', () => {
    const jws = compact({ typ: 'JWT', alg: 'ES256', x5c: ['MIIBkDCB'], iat: 1_780_000_000 }, base().build())

    expect(() => decodeWRPRC(jws)).toThrow(/rc-wrp\+jwt/)
  })

  it('parses header and payload without validating them', () => {
    const payload = { not: 'a wrprc' }
    const jws = compact({ typ: 'JWT', alg: 'ES256', x5c: ['MIIBkDCB'], iat: 1_780_000_000 }, payload)
    const parsed = parseWRPRC(jws)

    expect(parsed.payload).toEqual(payload)
    expect(parsed.signature).toBe('AAAA')
  })

  it('rejects a compact JWS that does not have three parts', () => {
    expect(() => parseWRPRC('only.two')).toThrow(/3 parts/)
  })
})

// ============================================================================
// Assertions
// ============================================================================

describe('assertValidWRPRC', () => {
  const header = { typ: 'rc-wrp+jwt' as const, alg: 'ES256' as const, x5c: ['MIIBkDCB'], iat: 1_780_000_000 }

  it('passes for a valid header and payload', () => {
    expect(() => assertValidWRPRC(header, base().build())).not.toThrow()
  })

  it('reports the offending side in the message', () => {
    expect(() => assertValidWRPRC({ ...header, typ: 'JWT' }, base().build())).toThrow(/header/)
    expect(() => assertValidWRPRC(header, { name: 'incomplete' })).toThrow(/payload/)
  })
})

// ============================================================================
// Remaining builder surface
// ============================================================================

describe('builder setters', () => {
  it('carries the optional Table 7 fields through to the payload', () => {
    const payload = base()
      .supervisoryAuthority({ email: 'dpa@example.test', phone: '+31 10 1234567', uri: 'https://dpa.test/form' })
      .policyId(['0.4.0.19475.3.1'])
      .certificatePolicy('https://registrar.test/cp')
      .certificateId('cert-1')
      .status({ status_list: { idx: 3, uri: 'https://status.test/1' } })
      .infoUri('https://example.test/info')
      .supportUri('https://example.test/support')
      .publicBody(false)
      .build()

    expect(payload.supervisory_authority?.email).toBe('dpa@example.test')
    expect(payload.policy_id).toEqual(['0.4.0.19475.3.1'])
    expect(payload.certificate_policy).toBe('https://registrar.test/cp')
    expect(payload.jti).toBe('cert-1')
    expect(payload.status?.status_list.idx).toBe(3)
    expect(payload.public_body).toBe(false)
  })

  it('groups service descriptions by language and appends whole groups', () => {
    const payload = base()
      .serviceDescription('Onboarding', 'en')
      .serviceDescription('Registrierung', 'de')
      .addServiceDescriptions([{ lang: 'en', value: 'Second service' }])
      .purposes([{ lang: 'en', value: 'Age check' }])
      .build()

    expect(payload.srv_description).toHaveLength(2)
    expect(payload.srv_description?.[1]).toEqual([{ lang: 'en', value: 'Second service' }])
    expect(payload.purpose).toEqual([{ lang: 'en', value: 'Age check' }])
  })

  it('does not add the same entitlement twice', () => {
    const payload = base().addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER).build()

    expect(payload.entitlements).toEqual([WRP_ENTITLEMENTS.SERVICE_PROVIDER])
  })

  it('defaults iat to now when not set', () => {
    const before = Math.floor(Date.now() / 1000)
    const payload = wrprc()
      .name('Example')
      .legalName('Example N.V.')
      .identifier('LEINL-1')
      .country('NL')
      .registryUri('https://registry.test/wrp')
      .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
      .build()

    expect(payload.iat).toBeGreaterThanOrEqual(before)
  })

  it('builds the credential metadata shorthands', () => {
    expect(credential().sdJwtMeta(['urn:eudi:pid:1']).build()).toEqual({
      format: 'dc+sd-jwt',
      meta: { vct_values: ['urn:eudi:pid:1'] },
    })
    expect(credential().mdocMeta('eu.europa.ec.eudi.pid.1').build()).toEqual({
      format: 'mso_mdoc',
      meta: { doctype_value: 'eu.europa.ec.eudi.pid.1' },
    })
  })

  it('requires format and meta on a credential', () => {
    expect(() => credential().build()).toThrow(/format/)
    expect(() => credential().format('dc+sd-jwt').build()).toThrow(/meta/)
  })

  it('creates a service provider payload from the factory', () => {
    const payload = createServiceProviderWRPRC(
      'Example',
      'Example N.V.',
      'LEINL-529900T8BM49AURSDO55',
      'NL',
      'https://registry.test/wrp'
    )

    expect(payload.entitlements).toEqual([WRP_ENTITLEMENTS.SERVICE_PROVIDER])
  })
})
