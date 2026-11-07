/**
 * Conformance tests for the spec-alignment fixes:
 *  - srv_description / purpose serialize localized text as `value` (Tables 7/9)
 *  - entitlements accept OID form as well as URI (GEN-5.2.4-03)
 *  - Table 10 fields: exp (<= 12 months after iat), intermediary{sub,sname}, act
 */

import { base64urlDecode, base64urlEncode, VALIDATION_CODES } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import {
  decodeRegistrationCertificateJwt,
  parseRegistrationCertificatePayload,
  REGISTRATION_CERTIFICATE_DIALECTS,
  REGISTRATION_CERTIFICATE_VALIDATION_CODES,
  registrationCertificate,
  signRegistrationCertificateJwt,
  toRegistrationCertificateDialect,
  validateRegistrationCertificate,
  validateRegistrationCertificateJwtHeader,
  validateRegistrationCertificatePayload,
  WRP_ENTITLEMENTS,
  zRegistrationCertificatePayload,
} from '../index'
import { signJwsCallback } from './context.mjs'

const base = () =>
  registrationCertificate()
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
    expect(validateRegistrationCertificatePayload(payload, payload.sub).valid).toBe(true)
  })
})

describe('Table 10 fields', () => {
  it('accepts exp within 12 months of iat', () => {
    const payload = base()
      .expiresAt(1_700_000_000 + 200 * 24 * 3600)
      .build()
    expect(validateRegistrationCertificatePayload(payload, payload.sub).valid).toBe(true)
  })

  it('rejects exp more than 12 months after iat', () => {
    const payload = base()
      .expiresAt(1_700_000_000 + 400 * 24 * 3600)
      .build()
    const result = validateRegistrationCertificatePayload(payload, payload.sub)
    expect(result.valid).toBe(false)
    expect(result.issues.some((issue) => issue.severity === 'error' && issue.code === 'exp_too_late')).toBe(true)
  })

  it('checks intermediary.sub against the access certificate subject', () => {
    const ok = base().intermediary({ sub: 'LEINL-INTERMEDIARY', sname: 'Intermediary BV' }).build()
    expect(validateRegistrationCertificatePayload(ok, 'LEINL-INTERMEDIARY').valid).toBe(true)

    const mismatch = base().intermediary({ sub: 'LEINL-INTERMEDIARY', sname: 'Intermediary BV' }).build()
    const result = validateRegistrationCertificatePayload(mismatch, 'LEINL-OTHER')
    expect(result.valid).toBe(false)
    expect(
      result.issues.some(
        (issue) =>
          issue.severity === 'error' &&
          issue.code === REGISTRATION_CERTIFICATE_VALIDATION_CODES.ACCESS_CERTIFICATE_IDENTITY_MISMATCH
      )
    ).toBe(true)
  })

  it('checks sub against the access certificate subject when there is no intermediary', () => {
    const payload = base().build()

    expect(validateRegistrationCertificatePayload(payload, payload.sub).valid).toBe(true)

    const result = validateRegistrationCertificatePayload(payload, 'LEINL-OTHER')
    expect(result.valid).toBe(false)
    expect(result.issues).toContainEqual(
      expect.objectContaining({
        severity: 'error',
        path: ['sub'],
        code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.ACCESS_CERTIFICATE_IDENTITY_MISMATCH,
      })
    )
  })

  it('carries public_body and intended_use_id through the builder', () => {
    const payload = base().publicBody(true).intendedUseId('use-123').build()
    expect(payload.public_body).toBe(true)
    expect(payload.intended_use_id).toBe('use-123')
  })
})

describe('validation codes', () => {
  it('exposes codes a calling application can branch on', () => {
    const payload = base()
      .expiresAt(1_700_000_000 + 400 * 24 * 3600)
      .build()
    const result = validateRegistrationCertificatePayload(payload, payload.sub)

    expect(result.issues.filter((issue) => issue.severity === 'error').map((issue) => issue.code)).toContain(
      REGISTRATION_CERTIFICATE_VALIDATION_CODES.EXP_TOO_LATE
    )
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
      .build()

  it('accepts the anticipated claims and intermediary.name spellings when parsing', () => {
    const draft = toRegistrationCertificateDialect(withNested(), REGISTRATION_CERTIFICATE_DIALECTS.DRAFT) as Record<
      string,
      any
    >

    expect(draft.credentials[0]).toHaveProperty('claims')
    expect(draft.credentials[0]).not.toHaveProperty('claim')
    expect(draft.intermediary).toEqual({ sub: 'LEINL-INTERMEDIARY', name: 'Intermediary BV' })

    expect(validateRegistrationCertificatePayload(draft, 'LEINL-INTERMEDIARY').valid).toBe(true)
    expect(parseRegistrationCertificatePayload(draft, 'LEINL-INTERMEDIARY')).toEqual(withNested())
  })

  it('emits the published spelling by default', () => {
    const payload = withNested()
    expect(toRegistrationCertificateDialect(payload, REGISTRATION_CERTIFICATE_DIALECTS.CURRENT)).toBe(payload)
  })

  it('signs in the requested dialect while reporting the canonical payload', async () => {
    const signed = await signRegistrationCertificateJwt({
      payload: withNested(),
      accessCertificateSub: 'LEINL-INTERMEDIARY',
      certificates: [TEST_CERT],
      signJwsCallback,
      dialect: REGISTRATION_CERTIFICATE_DIALECTS.DRAFT,
    })

    const onTheWire = JSON.parse(base64urlDecode(signed.jws.split('.')[1]))
    expect(onTheWire.credentials[0]).toHaveProperty('claims')
    expect(onTheWire.intermediary).toHaveProperty('name')

    // decoding maps back to the canonical v1.2.1 shape
    expect(decodeRegistrationCertificateJwt(signed.jws, 'LEINL-INTERMEDIARY').payload).toEqual(withNested())
  })

  it('rejects provides_attestations as scheme URLs', () => {
    const payload = {
      ...base().build(),
      provides_attestations: ['https://catalogue.test/schemes/age-over-18'],
    }

    expect(validateRegistrationCertificatePayload(payload, payload.sub).valid).toBe(false)
  })

  it('rejects claim queries inside provides_attestations', () => {
    const withClaim = {
      ...base().build(),
      provides_attestations: [{ format: 'dc+sd-jwt', meta: {}, claim: [{ path: ['given_name'] }] }],
    }
    const withDraftClaims = {
      ...base().build(),
      provides_attestations: [{ format: 'dc+sd-jwt', meta: {}, claims: [{ path: ['given_name'] }] }],
    }

    expect(validateRegistrationCertificatePayload(withClaim, withClaim.sub).valid).toBe(false)
    expect(validateRegistrationCertificatePayload(withDraftClaims, withDraftClaims.sub).valid).toBe(false)
  })
})

describe('GEN-5.2.1-04 JAdES B-B signature', () => {
  it('signs with a B-B protected header and decodes it back', async () => {
    const signed = await signRegistrationCertificateJwt({
      payload: base().build(),
      accessCertificateSub: 'LEINL-529900T8BM49AURSDO55',
      certificates: [TEST_CERT],
      signJwsCallback,
    })

    // Claimed signing time required by TS 119 182-1 for signatures generated now
    expect(signed.header.iat).toBeTypeOf('number')
    expect(signed.header.typ).toBe('rc-wrp+jwt')
    expect(signed.header.x5c).toHaveLength(1)
    expect(validateRegistrationCertificateJwtHeader(signed.header).valid).toBe(true)

    expect(decodeRegistrationCertificateJwt(signed.jws, 'LEINL-529900T8BM49AURSDO55').payload).toEqual(signed.payload)
  })

  it('rejects a registration certificate whose header has no claimed signing time', () => {
    const header = base64urlEncode(JSON.stringify({ typ: 'rc-wrp+jwt', alg: 'ES256', x5c: ['MIIBkDCB'] }))
    const payload = base64urlEncode(JSON.stringify(base().build()))

    expect(() => decodeRegistrationCertificateJwt(`${header}.${payload}.AAAA`, 'LEINL-529900T8BM49AURSDO55')).toThrow(
      /B-B/
    )
  })
})

describe('Annex C example', () => {
  it('parses the decoded registration certificate payload from the specification', () => {
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
    }

    expect(zRegistrationCertificatePayload.safeParse(annexC).success).toBe(true)
    expect(validateRegistrationCertificatePayload(annexC, annexC.intermediary.sub).valid).toBe(true)
  })
})

describe('issues', () => {
  it('reports errors and warnings in one list with severity and requirement', () => {
    const payload = base()
      .expiresAt(1_700_000_000 + 400 * 24 * 3600)
      .build()
    const result = validateRegistrationCertificatePayload(payload, payload.sub)

    expect(result.issues).toContainEqual({
      severity: 'error',
      code: REGISTRATION_CERTIFICATE_VALIDATION_CODES.EXP_TOO_LATE,
      path: ['exp'],
      message: 'exp must be at most 12 months after iat (GEN-5.2.4-08)',
      requirement: 'GEN-5.2.4-08',
    })
    expect(Object.keys(result)).toEqual(['valid', 'issues'])
  })

  it('reports exp before iat with the common code and the times as context', () => {
    const payload = base().expiresAt(1_600_000_000).build()
    const result = validateRegistrationCertificatePayload(payload, payload.sub)

    expect(result.issues).toContainEqual({
      severity: 'error',
      code: VALIDATION_CODES.EXPIRES_BEFORE_ISSUED,
      path: ['exp'],
      message: 'exp must be after iat',
      context: { issuedAt: new Date(payload.iat * 1000), expiresAt: new Date(1_600_000_000 * 1000) },
    })
  })

  it('reports a wrong typ with the common code and the expected and actual typ', () => {
    const result = validateRegistrationCertificateJwtHeader({
      typ: 'JWT',
      alg: 'ES256',
      x5c: ['MII'],
      iat: 1_700_000_000,
    })

    expect(result).toEqual({
      valid: false,
      issues: [
        {
          severity: 'error',
          code: VALIDATION_CODES.INVALID_TYP,
          path: ['typ'],
          message: 'typ must be rc-wrp+jwt',
          context: { expected: ['rc-wrp+jwt'], actual: 'JWT' },
        },
      ],
    })
    expect(
      validateRegistrationCertificateJwtHeader({ alg: 'ES256', x5c: ['MII'], iat: 1_700_000_000 }).issues.map(
        (issue) => issue.message
      )
    ).toEqual(['typ is missing, it must be rc-wrp+jwt'])
    expect(
      validateRegistrationCertificateJwtHeader({ typ: 'rc-wrp+jwt', alg: 'ES256', x5c: ['MII'], iat: 1_700_000_000 })
        .valid
    ).toBe(true)
  })

  it('prefixes header and payload issues and keeps array indices as numbers', () => {
    const payload = { ...base().build(), entitlements: [42] }
    const result = validateRegistrationCertificate({ alg: 'ES256' }, payload, 'LEINL-529900T8BM49AURSDO55')

    expect(result.valid).toBe(false)
    expect(result.issues.some((issue) => issue.path[0] === 'header')).toBe(true)
    expect(result.issues).toContainEqual(
      expect.objectContaining({ severity: 'error', path: ['payload', 'entitlements', 0] })
    )
  })
})
