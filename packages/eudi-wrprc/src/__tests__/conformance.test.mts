/**
 * Conformance tests for the spec-alignment fixes:
 *  - srv_description / purpose serialize localized text as `value` (Tables 7/9)
 *  - entitlements accept OID form as well as URI (GEN-5.2.4-03)
 *  - Table 10 fields: exp (<= 12 months after iat), intermediary{sub,sname}, act
 */

import { describe, expect, it } from 'vitest'
import { validateWRPRCPayload, WRP_ENTITLEMENTS, WRPRC_VALIDATION_CODES, wrprc } from '../index'

const base = () =>
  wrprc()
    .name('Example')
    .legalName('Example N.V.')
    .identifier('LEINL-529900T8BM49AURSDO55')
    .country('NL')
    .registryUri('https://registry.test/wrp')
    .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
    .issuedAt(1_700_000_000)

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
