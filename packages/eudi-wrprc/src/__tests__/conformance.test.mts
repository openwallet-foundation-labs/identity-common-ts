/**
 * Conformance tests for the spec-alignment fixes:
 *  - srv_description / purpose serialize localized text as `value` (Tables 7/9)
 *  - entitlements accept OID form as well as URI (GEN-5.2.4-03)
 *  - Table 10 fields: exp (<= 12 months after iat), intermediary{sub,sname}, act
 */

import { ES256 } from '@owf/crypto'
import { base64urlDecode, base64urlEncode } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import {
  decodeWRPRC,
  parseWRPRCPayload,
  signWRPRC,
  toWRPRCDialect,
  validateWRPRCJWTHeader,
  validateWRPRCPayload,
  WRP_ENTITLEMENTS,
  WRPRC_DIALECTS,
  WRPRC_VALIDATION_CODES,
  WRPRCPayloadSchema,
  wrprc,
} from '../index'

const base = () =>
  wrprc()
    .name('Example')
    .legalName('Example N.V.')
    .identifier('LEINL-529900T8BM49AURSDO55')
    .country('NL')
    .registryUri('https://registry.test/wrp')
    .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
    .issuedAt(1_700_000_000)

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

describe('localized values serialize as { lang, value }', () => {
  it('emits value (not content) for srv_description and purpose', () => {
    const payload = base().serviceDescription('Onboarding', 'en').addPurpose('Verify age', 'en').build()

    expect(payload.srv_description?.[0][0]).toEqual({ lang: 'en', value: 'Onboarding' })
    expect(payload.purpose?.[0]).toEqual({ lang: 'en', value: 'Verify age' })
  })
})

describe('entitlements accept OID form', () => {
  it('validates an entitlement given as an OID', () => {
    const payload = base().entitlements(['0.4.0.19475.1.1']).build()
    expect(validateWRPRCPayload(payload).valid).toBe(true)
  })
})

describe('Table 10 fields', () => {
  it('accepts exp within 12 months of iat', () => {
    const payload = base()
      .expiresAt(1_700_000_000 + 200 * 24 * 3600)
      .build()
    expect(validateWRPRCPayload(payload).valid).toBe(true)
  })

  it('rejects exp more than 12 months after iat', () => {
    const payload = base()
      .expiresAt(1_700_000_000 + 400 * 24 * 3600)
      .build()
    const result = validateWRPRCPayload(payload)
    expect(result.valid).toBe(false)
    expect(result.errors.some((e) => e.code === 'exp_too_late')).toBe(true)
  })

  it('requires act.sub to match intermediary.sub', () => {
    const ok = base()
      .intermediary({ sub: 'LEINL-INTERMEDIARY', sname: 'Intermediary BV' })
      .act({ sub: 'LEINL-INTERMEDIARY' })
      .build()
    expect(validateWRPRCPayload(ok).valid).toBe(true)

    const mismatch = base()
      .intermediary({ sub: 'LEINL-INTERMEDIARY', sname: 'Intermediary BV' })
      .act({ sub: 'LEINL-OTHER' })
      .build()
    const result = validateWRPRCPayload(mismatch)
    expect(result.valid).toBe(false)
    expect(result.errors.some((e) => e.code === 'act_intermediary_mismatch')).toBe(true)
  })

  it('carries public_body and intended_use_id through the builder', () => {
    const payload = base().publicBody(true).intendedUseId('use-123').build()
    expect(payload.public_body).toBe(true)
    expect(payload.intended_use_id).toBe('use-123')
  })
})

describe('validation codes', () => {
  it('exposes codes a calling application can branch on', () => {
    const result = validateWRPRCPayload(
      base()
        .expiresAt(1_700_000_000 + 400 * 24 * 3600)
        .build()
    )

    expect(result.errors.map((e) => e.code)).toContain(WRPRC_VALIDATION_CODES.EXP_TOO_LATE)
  })
})

describe('wire dialects', () => {
  const withNested = () =>
    base()
      .addCredential({
        format: 'dc+sd-jwt',
        meta: { vct_values: ['urn:eudi:pid:1'] },
        claim: [{ path: ['given_name'] }],
      })
      .intermediary({ sub: 'LEINL-INTERMEDIARY', sname: 'Intermediary BV' })
      .act({ sub: 'LEINL-INTERMEDIARY' })
      .build()

  it('accepts the anticipated claims and intermediary.name spellings when parsing', () => {
    const draft = toWRPRCDialect(withNested(), WRPRC_DIALECTS.DRAFT) as Record<string, any>

    expect(draft.credentials[0]).toHaveProperty('claims')
    expect(draft.credentials[0]).not.toHaveProperty('claim')
    expect(draft.intermediary).toEqual({ sub: 'LEINL-INTERMEDIARY', name: 'Intermediary BV' })

    expect(validateWRPRCPayload(draft).valid).toBe(true)
    expect(parseWRPRCPayload(draft)).toEqual(withNested())
  })

  it('emits the published spelling by default', () => {
    const payload = withNested()
    expect(toWRPRCDialect(payload, WRPRC_DIALECTS.CURRENT)).toBe(payload)
  })

  it('signs in the requested dialect while reporting the canonical payload', async () => {
    const { privateKey } = await ES256.generateKeyPair()
    const signed = await signWRPRC({
      payload: withNested(),
      certificates: [TEST_CERT],
      signer: await ES256.getSigner(privateKey),
      dialect: WRPRC_DIALECTS.DRAFT,
    })

    const onTheWire = JSON.parse(base64urlDecode(signed.jws.split('.')[1]))
    expect(onTheWire.credentials[0]).toHaveProperty('claims')
    expect(onTheWire.intermediary).toHaveProperty('name')

    // decoding maps back to the canonical v1.2.1 shape
    expect(decodeWRPRC(signed.jws).payload).toEqual(withNested())
  })

  it('accepts provides_attestations as scheme URLs', () => {
    const payload = base()
      .addProvidedAttestation('https://catalogue.test/schemes/age-over-18')
      .addPurpose('Issue attestations')
      .build()

    expect(payload.provides_attestations).toEqual(['https://catalogue.test/schemes/age-over-18'])
    expect(validateWRPRCPayload(payload).valid).toBe(true)
  })

  it('rejects mixing credential objects and scheme URLs', () => {
    expect(() =>
      base()
        .addProvidedAttestation({ format: 'dc+sd-jwt', meta: {} })
        .addProvidedAttestation('https://catalogue.test/schemes/age-over-18')
    ).toThrow(/all credentials or all scheme URLs/)
  })
})

describe('GEN-5.2.1-04 JAdES B-B signature', () => {
  it('signs with a B-B protected header and decodes it back', async () => {
    const { privateKey } = await ES256.generateKeyPair()
    const signed = await signWRPRC({
      payload: base().build(),
      certificates: [TEST_CERT],
      signer: await ES256.getSigner(privateKey),
    })

    // Claimed signing time required by TS 119 182-1 for signatures generated now
    expect(signed.header.iat).toBeTypeOf('number')
    expect(signed.header.typ).toBe('rc-wrp+jwt')
    expect(signed.header.x5c).toHaveLength(1)
    expect(validateWRPRCJWTHeader(signed.header).valid).toBe(true)

    expect(decodeWRPRC(signed.jws).payload).toEqual(signed.payload)
  })

  it('rejects a WRPRC whose header has no claimed signing time', () => {
    const header = base64urlEncode(JSON.stringify({ typ: 'rc-wrp+jwt', alg: 'ES256', x5c: ['MIIBkDCB'] }))
    const payload = base64urlEncode(JSON.stringify(base().build()))

    expect(() => decodeWRPRC(`${header}.${payload}.AAAA`)).toThrow(/B-B/)
  })
})

describe('Annex C example', () => {
  it('parses the decoded WRPRC payload from the specification', () => {
    const annexC = {
      name: 'Example Company',
      sub_ln: 'Example Company GmbH',
      sub: 'LEIXG-529900T8BM49AURSDO55',
      country: 'DE',
      registry_uri: 'https://registrar.com',
      srv_description: [
        [
          { lang: 'en-US', value: 'Awesome Service by Example Company' },
          { lang: 'de-DE', value: 'Super Dienst von Example Company' },
        ],
      ],
      entitlements: ['https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider'],
      privacy_policy: 'https://example.com/privacy-policy',
      info_uri: 'https://example.com/info',
      support_uri: 'https://example.com/support',
      supervisory_authority: {
        email: 'supervisory@dpa.com',
        phone: '+49 123 4567890',
        uri: 'https://dpa.com/supervisory-authority',
      },
      policy_id: ['0.4.0.19475.3.1'],
      certificate_policy: 'https://registrar.com/certificate-policy',
      iat: 1_683_000_000,
      status: { status_list: { idx: 0, uri: 'https://example.com/statuslists/1' } },
      purpose: [
        { lang: 'en-US', value: 'Required for checking the minimum age' },
        { lang: 'de-DE', value: 'Benötigt für die Überprüfung des Mindestalters' },
      ],
      credentials: [
        {
          format: 'dc+sd-jwt',
          meta: { vct_values: ['urn:eudi:pid:de:1'] },
          claim: [{ path: ['age_equal_or_over', '18'] }],
        },
        {
          format: 'mso_mdoc',
          meta: { doctype_value: 'eu.europa.ec.eudi.pid.1' },
          claim: [{ path: ['eu.europa.ec.eudi.pid.1', 'age_over_18'] }],
        },
      ],
      provides_attestations: [
        {
          format: 'dc+sd-jwt',
          meta: { vct_values: ['https://example.com/attestations/age_over_18'] },
        },
      ],
      // Annex C spells the intermediary common name `name`; Table 10 is normative and says `sname`
      intermediary: { sub: 'LEIXG-INTERMEDIARY-1234567890', sname: 'Intermediary Services Ltd.' },
      act: { sub: 'LEIXG-INTERMEDIARY-1234567890' },
    }

    expect(WRPRCPayloadSchema.safeParse(annexC).success).toBe(true)
    expect(validateWRPRCPayload(annexC).valid).toBe(true)
  })
})
