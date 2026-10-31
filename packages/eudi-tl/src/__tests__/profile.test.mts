import { describe, expect, it } from 'vitest'
import { type ProfileRule, TRUSTED_LIST_VALIDATION_CODES, validateTrustedListProfile } from '../index'

/**
 * Profile validation is caller-driven: the library validates a trusted list
 * against a {@link ProfileRule} supplied by the caller, so it stays agnostic to
 * any concrete ecosystem. These use synthetic, minimal lists.
 */
const list = (tslType: string, serviceTypeIdentifier: string, serviceStatus: string) => ({
  tslType,
  providers: [
    {
      services: [{ serviceTypeIdentifier, serviceStatus, digitalIdentities: [] }],
    },
  ],
})

const rule: ProfileRule = {
  name: 'example',
  tslType: 'https://example.org/lists/tsl-type',
  serviceTypes: ['https://example.org/service-type/issuance'],
  serviceStatuses: ['https://example.org/service-status/active'],
}

describe('validateTrustedListProfile', () => {
  it('accepts a list that matches the supplied profile rule', () => {
    const result = validateTrustedListProfile(
      list(rule.tslType, 'https://example.org/service-type/issuance', 'https://example.org/service-status/active'),
      rule
    )
    expect(result.valid).toBe(true)
  })

  it('compares scheme-insensitively (http vs https)', () => {
    const result = validateTrustedListProfile(
      list(
        'http://example.org/lists/tsl-type',
        'http://example.org/service-type/issuance',
        'http://example.org/service-status/active'
      ),
      rule
    )
    expect(result.valid).toBe(true)
  })

  it('reports a structured error for the wrong TSLType', () => {
    const result = validateTrustedListProfile(
      list(
        'https://example.org/other/tsl-type',
        'https://example.org/service-type/issuance',
        'https://example.org/service-status/active'
      ),
      rule
    )
    expect(result.valid).toBe(false)
    expect(result.errors.some((e) => e.path === 'tslType')).toBe(true)
  })

  it('rejects an unexpected service type / status', () => {
    const result = validateTrustedListProfile(
      list(rule.tslType, 'https://example.org/service-type/other', 'https://example.org/service-status/withdrawn'),
      rule
    )
    expect(result.valid).toBe(false)
    expect(result.errors.length).toBeGreaterThan(0)
  })

  it('reports each profile error as a finding pointing at the service', () => {
    const result = validateTrustedListProfile(
      list(rule.tslType, 'https://example.org/service-type/other', 'https://example.org/service-status/withdrawn'),
      rule
    )
    expect(result.findings).toEqual([
      {
        severity: 'error',
        code: TRUSTED_LIST_VALIDATION_CODES.UNEXPECTED_SERVICE_TYPE,
        path: ['providers', 0, 'services', 0, 'serviceTypeIdentifier'],
        message: '[example] unexpected service type https://example.org/service-type/other',
      },
      {
        severity: 'error',
        code: TRUSTED_LIST_VALIDATION_CODES.UNEXPECTED_SERVICE_STATUS,
        path: ['providers', 0, 'services', 0, 'serviceStatus'],
        message: '[example] unexpected service status https://example.org/service-status/withdrawn',
      },
    ])
    expect(result.errors.map((e) => e.path)).toEqual([
      'providers.0.services.0.serviceTypeIdentifier',
      'providers.0.services.0.serviceStatus',
    ])
  })

  it('reports schema issues as findings with the zod issue code', () => {
    const result = validateTrustedListProfile({ tslType: rule.tslType, providers: [{ services: [{}] }] }, rule)
    expect(result.valid).toBe(false)
    expect(result.findings.length).toBeGreaterThan(0)
    for (const finding of result.findings) {
      expect(finding).toMatchObject({ severity: 'error', code: expect.any(String) })
      expect(finding.path.slice(0, 4)).toEqual(['providers', 0, 'services', 0])
    }
  })

  it('passes when any of several rules matches', () => {
    const other: ProfileRule = {
      ...rule,
      tslType: 'https://example.org/other/tsl-type',
    }
    const result = validateTrustedListProfile(
      list(rule.tslType, 'https://example.org/service-type/issuance', 'https://example.org/service-status/active'),
      [other, rule]
    )
    expect(result.valid).toBe(true)
  })
})
