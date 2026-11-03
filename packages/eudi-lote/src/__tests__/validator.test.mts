import { decodeJwt } from '@owf/identity-common'
import { describe, expect, expectTypeOf, it } from 'vitest'
import {
  assertValidLote,
  getNotifiedTrustedEntities,
  LOTE_VALIDATION_CODES,
  LoteError,
  type LoteValidationError,
  validateLote,
} from '../index'
import { LOTE_TYPES } from '../profiles'
import type { CompatLoteDocument, LoteDocument } from '../types'
import { LoteProfile, type LoteProfileDocument, type ValidationResult, validateLoteProfile } from '../validator'
import {
  EUPIDProvidersJWT,
  GermanPIDProvidersJWT,
  GermanSandboxWalletProvidersJWT,
  LP26PIDProvidersEmptyJWT,
  LP26WRPRCProvidersEmptyJWT,
  NorwegianSandboxPIDProvidersJWT,
  NorwegianSandboxWalletProvidersJWT,
  NorwegianSandboxWRPACProvidersJWT,
  PubEAAProvidersJWT,
  WalletProvidersJWT,
  WRPACProvidersJWT,
} from './fixtures.mjs'

describe('LoTE Validator', () => {
  const createMinimalValidLote = (): LoteDocument => ({
    LoTE: {
      ListAndSchemeInformation: {
        LoTEVersionIdentifier: 1,
        LoTESequenceNumber: 1,
        SchemeOperatorName: [{ lang: 'en', value: 'Test Operator' }],
        ListIssueDateTime: '2024-01-01T00:00:00.000Z',
        NextUpdate: '2025-01-01T00:00:00.000Z',
      },
      TrustedEntitiesList: [],
    },
  })

  describe('validateLote', () => {
    it('should validate a minimal valid LoTE document', () => {
      const lote = createMinimalValidLote()
      const result = validateLote(lote)

      expect(result.valid).toBe(true)
      expect(result.issues).toHaveLength(0)
    })

    it('should reject null', () => {
      const result = validateLote(null)

      expect(result.valid).toBe(false)
      expect(result.issues[0].message).toContain('expected object')
    })

    it('should reject undefined', () => {
      const result = validateLote(undefined)

      expect(result.valid).toBe(false)
    })

    it('should reject non-object values', () => {
      expect(validateLote('string').valid).toBe(false)
      expect(validateLote(123).valid).toBe(false)
      expect(validateLote([]).valid).toBe(false)
    })

    it('should require LoTE field', () => {
      const result = validateLote({})

      expect(result.valid).toBe(false)
      expect(result.issues.some((issue) => issue.path.join('.') === 'LoTE')).toBe(true)
    })

    it('should require ListAndSchemeInformation', () => {
      const result = validateLote({ LoTE: {} })

      expect(result.valid).toBe(false)
      expect(result.issues.some((issue) => issue.path.join('.') === 'LoTE.ListAndSchemeInformation')).toBe(true)
    })
  })

  describe('ListAndSchemeInformation validation', () => {
    it('should require LoTEVersionIdentifier', () => {
      const lote = createMinimalValidLote()
      // @ts-expect-error - Testing invalid input
      delete lote.LoTE.ListAndSchemeInformation.LoTEVersionIdentifier

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
      expect(
        result.issues.some((issue) => issue.path.join('.') === 'LoTE.ListAndSchemeInformation.LoTEVersionIdentifier')
      ).toBe(true)
    })

    it('should require LoTESequenceNumber', () => {
      const lote = createMinimalValidLote()
      // @ts-expect-error - Testing invalid input
      delete lote.LoTE.ListAndSchemeInformation.LoTESequenceNumber

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
      expect(
        result.issues.some((issue) => issue.path.join('.') === 'LoTE.ListAndSchemeInformation.LoTESequenceNumber')
      ).toBe(true)
    })

    it('should require SchemeOperatorName', () => {
      const lote = createMinimalValidLote()
      // @ts-expect-error - Testing invalid input
      delete lote.LoTE.ListAndSchemeInformation.SchemeOperatorName

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
      expect(
        result.issues.some((issue) => issue.path.join('.') === 'LoTE.ListAndSchemeInformation.SchemeOperatorName')
      ).toBe(true)
    })

    it('should require non-empty SchemeOperatorName array', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.ListAndSchemeInformation.SchemeOperatorName = []

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
    })

    it('should require valid ListIssueDateTime', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.ListAndSchemeInformation.ListIssueDateTime = 'invalid-date'

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
      expect(
        result.issues.some((issue) => issue.path.join('.') === 'LoTE.ListAndSchemeInformation.ListIssueDateTime')
      ).toBe(true)
    })

    it('should require valid NextUpdate', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.ListAndSchemeInformation.NextUpdate = 'not-a-date'

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
      expect(result.issues.some((issue) => issue.path.join('.') === 'LoTE.ListAndSchemeInformation.NextUpdate')).toBe(
        true
      )
    })

    it('should validate optional URI fields', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.ListAndSchemeInformation.LoTEType = 'not-a-uri'
      lote.LoTE.ListAndSchemeInformation.DistributionPoints = ['not-a-uri']

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
      expect(result.issues.some((issue) => issue.path.join('.') === 'LoTE.ListAndSchemeInformation.LoTEType')).toBe(
        true
      )
      expect(
        result.issues.some((issue) => issue.path.join('.') === 'LoTE.ListAndSchemeInformation.DistributionPoints.0')
      ).toBe(true)
    })

    it('should validate SchemeTerritory is 2-character code', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.ListAndSchemeInformation.SchemeTerritory = 'GERMANY'

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
      expect(
        result.issues.some((issue) => issue.path.join('.') === 'LoTE.ListAndSchemeInformation.SchemeTerritory')
      ).toBe(true)
    })

    it('should accept valid 2-character SchemeTerritory', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.ListAndSchemeInformation.SchemeTerritory = 'DE'

      const result = validateLote(lote)

      expect(result.valid).toBe(true)
    })
  })

  describe('PointersToOtherLoTE validation', () => {
    it('should validate PointersToOtherLoTE structure', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.ListAndSchemeInformation.PointersToOtherLoTE = [
        {
          LoTELocation: 'https://example.com/lote',
          ServiceDigitalIdentities: [{ PublicKeyValues: [{ kty: 'EC' }] }],
          LoTEQualifiers: [
            {
              LoTEType: 'https://example.com/type',
              SchemeOperatorName: [{ lang: 'en', value: 'Other Operator' }],
              MimeType: 'application/json',
            },
          ],
        },
      ]

      const result = validateLote(lote)

      expect(result.valid).toBe(true)
    })

    it('should reject invalid LoTELocation URI', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.ListAndSchemeInformation.PointersToOtherLoTE = [
        {
          LoTELocation: 'not-a-uri',
          ServiceDigitalIdentities: [{ PublicKeyValues: [{ kty: 'EC' }] }],
          LoTEQualifiers: [
            {
              LoTEType: 'https://example.com/type',
              SchemeOperatorName: [{ lang: 'en', value: 'Operator' }],
              MimeType: 'application/json',
            },
          ],
        },
      ]

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
    })
  })

  describe('TrustedEntity validation', () => {
    it('should validate trusted entities with services', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.TrustedEntitiesList = [
        {
          TrustedEntityInformation: {
            TEName: [{ lang: 'en', value: 'Test Entity' }],
            TEAddress: {
              TEPostalAddress: [
                {
                  lang: 'en',
                  StreetAddress: '123 St',
                  Locality: 'City',
                  PostalCode: '12345',
                  Country: 'DE',
                },
              ],
              TEElectronicAddress: [{ lang: 'en', uriValue: 'mailto:test@example.com' }],
            },
          },
          TrustedEntityServices: [
            {
              ServiceInformation: {
                ServiceName: [{ lang: 'en', value: 'Test Service' }],
                ServiceDigitalIdentity: {
                  PublicKeyValues: [{ kty: 'EC', crv: 'P-256' }],
                },
              },
            },
          ],
        },
      ]

      const result = validateLote(lote)

      expect(result.valid).toBe(true)
    })

    it('should validate optional URI fields', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.TrustedEntitiesList = [
        {
          TrustedEntityInformation: {
            TEName: [{ lang: 'en', value: 'Test Entity' }],
            TEAddress: {
              TEPostalAddress: [
                {
                  lang: 'en',
                  StreetAddress: '123 St',
                  Locality: 'City',
                  PostalCode: '12345',
                  Country: 'DE',
                },
              ],
              TEElectronicAddress: [{ lang: 'en', uriValue: 'mailto:test@example.com' }],
            },
          },
          TrustedEntityServices: [
            {
              ServiceInformation: {
                ServiceName: [{ lang: 'en', value: 'Test Service' }],
                ServiceDigitalIdentity: {
                  PublicKeyValues: [{ kty: 'EC', crv: 'P-256' }],
                },
                ServiceSupplyPoints: [
                  {
                    ServiceType: 'https://example.com/service-type',
                    uriValue: 'not-a-uri',
                  },
                ],
              },
            },
          ],
        },
      ]

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
      expect(
        result.issues.some(
          (issue) =>
            issue.path.join('.') ===
            'LoTE.TrustedEntitiesList.0.TrustedEntityServices.0.ServiceInformation.ServiceSupplyPoints.0.uriValue'
        )
      ).toBe(true)
    })

    it('should require at least one service per entity', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.TrustedEntitiesList = [
        {
          TrustedEntityInformation: {
            TEName: [{ lang: 'en', value: 'Test Entity' }],
            TEAddress: {
              TEPostalAddress: [],
              TEElectronicAddress: [],
            },
          },
          TrustedEntityServices: [],
        },
      ]

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
      expect(result.issues.some((issue) => issue.path.includes('TrustedEntityServices'))).toBe(true)
    })

    it('should require service name', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.TrustedEntitiesList = [
        {
          TrustedEntityInformation: {
            TEName: [{ lang: 'en', value: 'Entity' }],
            TEAddress: { TEPostalAddress: [], TEElectronicAddress: [] },
          },
          TrustedEntityServices: [
            {
              ServiceInformation: {
                ServiceName: [],
                ServiceDigitalIdentity: { PublicKeyValues: [{ kty: 'EC' }] },
              },
            },
          ],
        },
      ]

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
    })

    it('should require digital identity with at least one type', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.TrustedEntitiesList = [
        {
          TrustedEntityInformation: {
            TEName: [{ lang: 'en', value: 'Entity' }],
            TEAddress: { TEPostalAddress: [], TEElectronicAddress: [] },
          },
          TrustedEntityServices: [
            {
              ServiceInformation: {
                ServiceName: [{ lang: 'en', value: 'Service' }],
                ServiceDigitalIdentity: {},
              },
            },
          ],
        },
      ]

      const result = validateLote(lote)

      // The TS 119 602 JSON schema allows an empty ServiceDigitalIdentity; the EU profiles do not
      expect(result).toMatchObject({ valid: true, issues: [] })
    })
  })

  describe('ServiceHistory validation', () => {
    it('should validate service history entries', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.TrustedEntitiesList = [
        {
          TrustedEntityInformation: {
            TEName: [{ lang: 'en', value: 'Entity' }],
            TEAddress: { TEPostalAddress: [], TEElectronicAddress: [] },
          },
          TrustedEntityServices: [
            {
              ServiceInformation: {
                ServiceName: [{ lang: 'en', value: 'Service' }],
                ServiceDigitalIdentity: { PublicKeyValues: [{ kty: 'EC' }] },
              },
              ServiceHistory: [
                {
                  ServiceName: [{ lang: 'en', value: 'Old Name' }],
                  ServiceDigitalIdentity: { PublicKeyValues: [{ kty: 'EC' }] },
                  ServiceStatus: 'https://example.com/status/revoked',
                  StatusStartingTime: '2023-01-01T00:00:00.000Z',
                },
              ],
            },
          ],
        },
      ]

      const result = validateLote(lote)

      expect(result.valid).toBe(true)
    })

    it('should reject invalid service history status URI', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.TrustedEntitiesList = [
        {
          TrustedEntityInformation: {
            TEName: [{ lang: 'en', value: 'Entity' }],
            TEAddress: { TEPostalAddress: [], TEElectronicAddress: [] },
          },
          TrustedEntityServices: [
            {
              ServiceInformation: {
                ServiceName: [{ lang: 'en', value: 'Service' }],
                ServiceDigitalIdentity: { PublicKeyValues: [{ kty: 'EC' }] },
              },
              ServiceHistory: [
                {
                  ServiceName: [{ lang: 'en', value: 'Old' }],
                  ServiceDigitalIdentity: { PublicKeyValues: [{ kty: 'EC' }] },
                  ServiceStatus: 'not-a-uri',
                  StatusStartingTime: '2023-01-01T00:00:00.000Z',
                },
              ],
            },
          ],
        },
      ]

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
    })
  })

  describe('TS 119 602 v1.1.1 JSON schema', () => {
    const createTrustedEntity = (
      postalAddress: Record<string, string>,
      supplyPoints: Record<string, string>[]
    ): Record<string, unknown> => ({
      TrustedEntityInformation: {
        TEName: [{ lang: 'en', value: 'Test Entity' }],
        TEAddress: {
          TEPostalAddress: [postalAddress],
          TEElectronicAddress: [{ lang: 'en', uriValue: 'mailto:test@example.com' }],
        },
      },
      TrustedEntityServices: [
        {
          ServiceInformation: {
            ServiceName: [{ lang: 'en', value: 'Test Service' }],
            ServiceDigitalIdentity: { X509SKIs: ['dGVzdA=='] },
            ServiceSupplyPoints: supplyPoints,
          },
        },
      ],
    })

    const withEntity = (entity: Record<string, unknown>) => {
      const lote = createMinimalValidLote()
      return { LoTE: { ...lote.LoTE, TrustedEntitiesList: [entity] } }
    }

    const fullAddress = { lang: 'en', StreetAddress: '123 St', Locality: 'City', PostalCode: '12345', Country: 'DE' }

    it('should accept a list without TrustedEntitiesList', () => {
      const { LoTE } = createMinimalValidLote()
      const { TrustedEntitiesList: _, ...withoutEntities } = LoTE

      expect(validateLote({ LoTE: withoutEntities })).toMatchObject({ valid: true, issues: [] })
    })

    it('should accept a service supply point without ServiceType', () => {
      const lote = withEntity(createTrustedEntity(fullAddress, [{ uriValue: 'https://issuer.example.com/' }]))

      expect(validateLote(lote)).toMatchObject({ valid: true, issues: [] })
    })

    it('should still require uriValue on a service supply point', () => {
      const lote = withEntity(createTrustedEntity(fullAddress, [{ ServiceType: 'https://example.com/type' }]))
      const result = validateLote(lote)

      expect(result.valid).toBe(false)
      expect(result.issues.map((issue) => issue.path.join('.'))).toEqual([
        'LoTE.TrustedEntitiesList.0.TrustedEntityServices.0.ServiceInformation.ServiceSupplyPoints.0.uriValue',
      ])
    })

    it('should accept a postal address without Locality and PostalCode', () => {
      const lote = withEntity(
        createTrustedEntity({ lang: 'en', StreetAddress: '123 St', Country: 'DE' }, [
          { uriValue: 'https://issuer.example.com/' },
        ])
      )

      expect(validateLote(lote)).toMatchObject({ valid: true, issues: [] })
    })

    it('should still require StreetAddress and Country on a postal address', () => {
      const lote = withEntity(
        createTrustedEntity({ lang: 'en', Locality: 'City', PostalCode: '12345' }, [
          { uriValue: 'https://issuer.example.com/' },
        ])
      )
      const result = validateLote(lote)

      expect(result.valid).toBe(false)
      expect(result.issues.map((issue) => issue.path.join('.'))).toEqual([
        'LoTE.TrustedEntitiesList.0.TrustedEntityInformation.TEAddress.TEPostalAddress.0.StreetAddress',
        'LoTE.TrustedEntitiesList.0.TrustedEntityInformation.TEAddress.TEPostalAddress.0.Country',
      ])
    })

    it('should accept LoTELegalNotice as a plain string or a localized string', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.ListAndSchemeInformation.PolicyOrLegalNotice = [
        { LoTELegalNotice: 'Legal notice' },
        { LoTELegalNotice: { lang: 'en', value: 'Legal notice' } },
      ]

      expect(validateLote(lote)).toMatchObject({ valid: true, issues: [] })
    })

    it('should reject an empty LoTELegalNotice object', () => {
      const lote = createMinimalValidLote()
      const result = validateLote({
        LoTE: {
          ...lote.LoTE,
          ListAndSchemeInformation: {
            ...lote.LoTE.ListAndSchemeInformation,
            PolicyOrLegalNotice: [{ LoTELegalNotice: {} }],
          },
        },
      })

      expect(result.valid).toBe(false)
      expect(result.issues.map((issue) => issue.path.join('.'))).toContain(
        'LoTE.ListAndSchemeInformation.PolicyOrLegalNotice.0.LoTELegalNotice'
      )
    })

    const withPolicyOrLegalNotice = (items: unknown[]) => {
      const lote = createMinimalValidLote()
      return {
        LoTE: {
          ...lote.LoTE,
          ListAndSchemeInformation: { ...lote.LoTE.ListAndSchemeInformation, PolicyOrLegalNotice: items },
        },
      }
    }
    const policy = { LoTEPolicy: { lang: 'en', uriValue: 'https://example.com/policy' } }

    it('should accept an empty string legal notice, as the JSON schema does', () => {
      expect(validateLote(withPolicyOrLegalNotice([{ LoTELegalNotice: '' }]))).toMatchObject({
        valid: true,
        issues: [],
      })
    })

    it('should reject a PolicyOrLegalNotice item with neither LoTEPolicy nor LoTELegalNotice', () => {
      const result = validateLote(withPolicyOrLegalNotice([{}]))

      expect(result.valid).toBe(false)
      expect(result.issues.map((issue) => issue.path.join('.'))).toEqual([
        'LoTE.ListAndSchemeInformation.PolicyOrLegalNotice.0',
      ])
    })

    it('should reject a PolicyOrLegalNotice whose every item has both LoTEPolicy and LoTELegalNotice', () => {
      const result = validateLote(withPolicyOrLegalNotice([{ ...policy, LoTELegalNotice: 'Notice' }]))

      expect(result.valid).toBe(false)
      expect(result.issues.map((issue) => issue.path.join('.'))).toEqual([
        'LoTE.ListAndSchemeInformation.PolicyOrLegalNotice',
      ])
    })

    it('should accept an item with both keys when another item has only one, as the oneOf does', () => {
      expect(validateLote(withPolicyOrLegalNotice([policy, { ...policy, LoTELegalNotice: 'Notice' }]))).toMatchObject({
        valid: true,
        issues: [],
      })
    })

    it('should reject an empty PolicyOrLegalNotice', () => {
      const result = validateLote(withPolicyOrLegalNotice([]))

      expect(result.issues.map((issue) => issue.path.join('.'))).toEqual([
        'LoTE.ListAndSchemeInformation.PolicyOrLegalNotice',
      ])
    })

    it('should reject policies and legal notices mixed in one PolicyOrLegalNotice', () => {
      const result = validateLote(withPolicyOrLegalNotice([policy, { LoTELegalNotice: 'Notice' }]))

      expect(result.valid).toBe(false)
      expect(result.issues.map((issue) => issue.path.join('.'))).toEqual([
        'LoTE.ListAndSchemeInformation.PolicyOrLegalNotice.1',
      ])
    })

    it('should accept date-times with an offset (RFC 3339)', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.ListAndSchemeInformation.ListIssueDateTime = '2026-10-23T10:47:49+02:00'
      lote.LoTE.ListAndSchemeInformation.NextUpdate = '2027-04-23T10:47:49-05:30'

      expect(validateLote(lote)).toMatchObject({ valid: true, issues: [] })
    })

    it('should accept lowercase t and z and a leap second at 23:59:60 UTC (RFC 3339)', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.ListAndSchemeInformation.ListIssueDateTime = '2016-12-31t23:59:60z'
      lote.LoTE.ListAndSchemeInformation.NextUpdate = '2017-01-01T00:59:60+01:00'

      expect(validateLote(lote)).toMatchObject({ valid: true, issues: [] })
    })

    it('should reject a leap second outside 23:59 UTC and an impossible date', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.ListAndSchemeInformation.ListIssueDateTime = '2016-12-31T22:59:60Z'
      lote.LoTE.ListAndSchemeInformation.NextUpdate = '2026-02-29T00:00:00Z'

      expect(validateLote(lote).issues.map((issue) => issue.path.join('.'))).toEqual([
        'LoTE.ListAndSchemeInformation.ListIssueDateTime',
        'LoTE.ListAndSchemeInformation.NextUpdate',
      ])
    })

    it('should accept what the JSON schema leaves open: any certificate encoding and specRef, empty strings, a long country', () => {
      const lote = withEntity({
        TrustedEntityInformation: {
          TEName: [{ lang: '', value: '' }],
          TEAddress: {
            TEPostalAddress: [{ lang: 'en', StreetAddress: '1 St', Country: 'Germany' }],
            TEElectronicAddress: [{ lang: 'en', uriValue: 'mailto:test@example.com' }],
          },
        },
        TrustedEntityServices: [
          {
            ServiceInformation: {
              ServiceName: [{ lang: 'en', value: 'Service' }],
              ServiceDigitalIdentity: {
                X509Certificates: [{ encoding: 'https://example.com/der', specRef: 'X.509', val: '' }],
              },
            },
          },
        ],
      })
      lote.LoTE.ListAndSchemeInformation = {
        ...lote.LoTE.ListAndSchemeInformation,
        PointersToOtherLoTE: [
          {
            LoTELocation: 'https://example.com/lote.json',
            ServiceDigitalIdentities: [{}],
            LoTEQualifiers: [
              { LoTEType: 'https://example.com/type', SchemeOperatorName: [{ lang: 'en', value: 'Op' }], MimeType: '' },
            ],
          },
        ],
      }

      expect(validateLote(lote)).toMatchObject({ valid: true, issues: [] })
    })

    it('should still reject a certificate encoding that is not a URI', () => {
      const lote = withEntity({
        TrustedEntityInformation: {
          TEName: [{ lang: 'en', value: 'Entity' }],
          TEAddress: {
            TEPostalAddress: [fullAddress],
            TEElectronicAddress: [{ lang: 'en', uriValue: 'mailto:a@example.com' }],
          },
        },
        TrustedEntityServices: [
          {
            ServiceInformation: {
              ServiceName: [{ lang: 'en', value: 'Service' }],
              ServiceDigitalIdentity: { X509Certificates: [{ encoding: 'not a uri', val: 'AA==' }] },
            },
          },
        ],
      })

      expect(validateLote(lote).issues.map((issue) => issue.path.join('.'))).toEqual([
        'LoTE.TrustedEntitiesList.0.TrustedEntityServices.0.ServiceInformation.ServiceDigitalIdentity.X509Certificates.0.encoding',
      ])
    })
  })

  describe('assertValidLote', () => {
    it('should not throw for valid LoTE document', () => {
      const lote = createMinimalValidLote()

      expect(() => assertValidLote(lote)).not.toThrow()
    })

    it('should throw for invalid LoTE document', () => {
      expect(() => assertValidLote({})).toThrow('Invalid LoTE document')
    })

    it('should include error details in thrown error', () => {
      try {
        assertValidLote({ LoTE: {} })
        expect.fail('Should have thrown')
      } catch (error) {
        expect((error as Error).message).toContain('ListAndSchemeInformation')
        expect(error).toBeInstanceOf(LoteError)
        expect((error as LoteValidationError).issues).toEqual(validateLote({ LoTE: {} }).issues)
      }
    })
  })

  describe('validateLoteProfile', () => {
    it('should validate against EuPidProvidersList profile', () => {
      const { payload: lote } = decodeJwt(EUPIDProvidersJWT)
      const result = validateLoteProfile(lote, LoteProfile.EuPidProvidersList)

      expect(result.valid).toBe(true)
    })

    it('should validate against EuWalletProvidersList profile', () => {
      const { payload: lote } = decodeJwt(WalletProvidersJWT)
      const result = validateLoteProfile(lote, LoteProfile.EuWalletProvidersList)

      expect(result.valid).toBe(true)
    })

    it('should validate against EuWrpacProvidersList profile', () => {
      const { payload: lote } = decodeJwt(WRPACProvidersJWT)
      const result = validateLoteProfile(lote, LoteProfile.EuWrpacProvidersList)

      expect(result.valid).toBe(true)
    })

    it('should validate against EuPubEaaProvidersList profile', () => {
      const { payload: lote } = decodeJwt(PubEAAProvidersJWT)
      const result = validateLoteProfile(lote, LoteProfile.EuPubEaaProvidersList)

      expect(result.valid).toBe(true)
    })

    it('should validate an EC list without trusted entities against EuPidProvidersList profile', () => {
      const { payload: lote } = decodeJwt<any, LoteDocument>(LP26PIDProvidersEmptyJWT)

      expect(lote.LoTE.TrustedEntitiesList).toBeUndefined()
      expect(validateLote(lote)).toMatchObject({ valid: true, issues: [] })
      expect(validateLoteProfile(lote, LoteProfile.EuPidProvidersList)).toMatchObject({ valid: true, issues: [] })
    })

    it('should validate an EC list with a plain string legal notice against EuWrprcProvidersList profile', () => {
      const { payload: lote } = decodeJwt<any, LoteDocument>(LP26WRPRCProvidersEmptyJWT)

      expect(lote.LoTE.ListAndSchemeInformation.PolicyOrLegalNotice).toEqual([{ LoTELegalNotice: 'Legal notice' }])
      expect(validateLote(lote)).toMatchObject({ valid: true, issues: [] })
      expect(validateLoteProfile(lote, LoteProfile.EuWrprcProvidersList)).toMatchObject({ valid: true, issues: [] })
    })

    /** The EC WRPAC list, turned into a list of another EU profile by its URIs */
    const asProfile = (kind: 'EAA' | 'PubEAA') => {
      const { payload } = decodeJwt<any, LoteDocument>(WRPACProvidersJWT)
      const json = JSON.stringify(payload)
        .replace(/LoTEType\/EUWRPACProvidersList/g, `LoTEType/EU${kind}ProvidersList`)
        .replace(/WRPACProvidersList\//g, `${kind}ProvidersList/`)
        .replace(/ListOfTrustedEntities\/WRPACProvider\//g, `ListOfTrustedEntities/${kind}Provider/`)
        .replace(/SvcType\/WRPAC\//g, `SvcType/${kind}/`)
      const lote = JSON.parse(json) as LoteDocument
      if (kind === 'PubEAA') {
        lote.LoTE.ListAndSchemeInformation.HistoricalInformationPeriod = 65535
        for (const service of lote.LoTE.TrustedEntitiesList?.flatMap((e) => e.TrustedEntityServices) ?? []) {
          service.ServiceInformation.ServiceStatus = 'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified'
        }
      }
      return lote
    }

    it('should validate a list against the EUEAAProvidersList profile', () => {
      const lote = asProfile('EAA')

      expect(lote.LoTE.ListAndSchemeInformation.LoTEType).toBe(LOTE_TYPES.EuEaaProvidersList)
      expect(validateLoteProfile(lote, LoteProfile.EuEaaProvidersList)).toMatchObject({ valid: true, issues: [] })
    })

    it('should validate a list against the EUPubEAAProvidersList profile', () => {
      const lote = asProfile('PubEAA')

      expect(lote.LoTE.ListAndSchemeInformation.LoTEType).toBe(LOTE_TYPES.EuPubEaaProvidersList)
      expect(validateLoteProfile(lote, LoteProfile.EuPubEaaProvidersList)).toMatchObject({ valid: true, issues: [] })
    })

    it('should require a ServiceStatus of TS 119 602 H in the EUPubEAAProvidersList profile', () => {
      const statusErrors = (ServiceStatus: string | undefined, StatusStartingTime?: string) => {
        const lote = asProfile('PubEAA')
        const information = lote.LoTE.TrustedEntitiesList?.[0]?.TrustedEntityServices[0]?.ServiceInformation
        if (!information) throw new Error('The PubEAA list has no service')
        Object.assign(information, { ServiceStatus, StatusStartingTime })
        return validateLoteProfile(lote, LoteProfile.EuPubEaaProvidersList).issues.map((issue) => issue.message)
      }
      const statuses = 'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus'

      expect(statusErrors(`${statuses}/withdrawn`, '2026-05-01T00:00:00Z')).toEqual([])
      expect(statusErrors(undefined)).toEqual(['Profile EuPubEaaProvidersList: ServiceStatus must be present'])
      expect(statusErrors('http://uri.etsi.org/19602/PidProvidersList/SvcStatus/notified')).toEqual([
        `Profile EuPubEaaProvidersList: ServiceStatus must be one of the following: ${statuses}/notified, ${statuses}/withdrawn`,
      ])
    })

    it('should leave out withdrawn services and the entities without a notified service', () => {
      const lote = asProfile('PubEAA')
      const entities = lote.LoTE.TrustedEntitiesList ?? []
      const withdrawn = 'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn'
      const [first, second] = entities.map((e) => e.TrustedEntityServices)
      if (!first?.[0] || !second?.[0]) throw new Error('The PubEAA list has fewer than two services')
      first[0].ServiceInformation.ServiceStatus = withdrawn
      second.push({ ...second[0], ServiceInformation: { ...second[0].ServiceInformation, ServiceStatus: withdrawn } })

      const result = validateLoteProfile(lote, LoteProfile.EuPubEaaProvidersList)
      if (!result.valid) throw new Error('A list with withdrawn services is valid')
      const notified = getNotifiedTrustedEntities(result.lote)
      expect(result.notifiedTrustedEntities).toEqual(notified)

      expect(notified).toEqual(
        entities.slice(1).map((e, i) => (i === 0 ? { ...e, TrustedEntityServices: [e.TrustedEntityServices[0]] } : e))
      )
      expect(lote.LoTE.TrustedEntitiesList?.[1]?.TrustedEntityServices).toHaveLength(2)
      expectTypeOf(notified).toEqualTypeOf<
        NonNullable<LoteProfileDocument<LoteProfile.EuPubEaaProvidersList>['LoTE']['TrustedEntitiesList']>
      >()
    })

    it('should keep every service of a profile without ServiceStatus', () => {
      const result = validateLoteProfile(decodeJwt(WRPACProvidersJWT).payload, LoteProfile.EuWrpacProvidersList)
      if (!result.valid) throw new Error('The WRPAC list is valid')

      expect(getNotifiedTrustedEntities(result.lote)).toEqual(result.lote.LoTE.TrustedEntitiesList)
    })

    it('should keep requiring a 2-letter country and a digital identity in the EU profiles', () => {
      const { payload: lote } = decodeJwt<any, LoteDocument>(WRPACProvidersJWT)
      const entity = lote.LoTE.TrustedEntitiesList?.[0]
      const address = entity?.TrustedEntityInformation.TEAddress.TEPostalAddress[0]
      const firstService = entity?.TrustedEntityServices[0]
      if (!address || !firstService) throw new Error('The WRPAC fixture has no entity with an address and a service')
      address.Country = 'Germany'
      firstService.ServiceInformation.ServiceDigitalIdentity = {}

      expect(validateLote(lote)).toMatchObject({ valid: true, issues: [] })
      const result = validateLoteProfile(lote, LoteProfile.EuWrpacProvidersList)
      expect(result.valid).toBe(false)
      expect(result.issues.map((issue) => issue.path.join('.'))).toEqual([
        'LoTE.TrustedEntitiesList.0.TrustedEntityInformation.TEAddress.TEPostalAddress.0.Country',
        'LoTE.TrustedEntitiesList.0.TrustedEntityServices.0.ServiceInformation.ServiceDigitalIdentity',
      ])
    })

    it('should keep the rules the base schema used to apply in the EU profiles', () => {
      const { payload: lote } = decodeJwt<any, LoteDocument>(WRPACProvidersJWT)
      const info = lote.LoTE.ListAndSchemeInformation
      const entity = lote.LoTE.TrustedEntitiesList?.[0]
      const firstService = entity?.TrustedEntityServices[0]
      if (!entity || !firstService) throw new Error('The WRPAC fixture has no entity with a service')
      info.SchemeOperatorName = [{ lang: '', value: '' }]
      info.SchemeOperatorAddress = {
        SchemeOperatorPostalAddress: [{ lang: 'en', StreetAddress: '1 Rue', Country: 'Belgium' }],
        SchemeOperatorElectronicAddress: [{ lang: 'en', uriValue: 'mailto:op@example.com' }],
      }
      info.PointersToOtherLoTE = [
        {
          LoTELocation: 'https://example.com/other.json',
          ServiceDigitalIdentities: [{}],
          LoTEQualifiers: [
            { LoTEType: 'https://example.com/type', SchemeOperatorName: [{ lang: 'en', value: 'Op' }], MimeType: '' },
          ],
        },
      ]
      firstService.ServiceInformation.ServiceDigitalIdentity = {
        X509Certificates: [{ encoding: 'https://example.com/der', specRef: 'X.509', val: '' }],
        PublicKeyValues: [{ kty: 'oct' }],
      }
      firstService.ServiceHistory = [
        {
          ServiceName: [{ lang: 'en', value: 'Old' }],
          ServiceDigitalIdentity: {},
          ServiceStatus: 'https://example.com/status',
          StatusStartingTime: '2026-01-01T00:00:00Z',
        },
      ]

      expect(validateLote(lote)).toMatchObject({ valid: true, issues: [] })
      const paths = validateLoteProfile(lote, LoteProfile.EuWrpacProvidersList).issues.map((issue) =>
        issue.path.join('.')
      )
      const service = 'LoTE.TrustedEntitiesList.0.TrustedEntityServices.0'
      expect(paths).toEqual(
        expect.arrayContaining([
          'LoTE.ListAndSchemeInformation.SchemeOperatorName.0.lang',
          'LoTE.ListAndSchemeInformation.SchemeOperatorName.0.value',
          'LoTE.ListAndSchemeInformation.SchemeOperatorAddress.SchemeOperatorPostalAddress.0.Country',
          'LoTE.ListAndSchemeInformation.PointersToOtherLoTE.0.ServiceDigitalIdentities.0',
          'LoTE.ListAndSchemeInformation.PointersToOtherLoTE.0.LoTEQualifiers.0.MimeType',
          `${service}.ServiceInformation.ServiceDigitalIdentity.X509Certificates.0.val`,
          `${service}.ServiceInformation.ServiceDigitalIdentity.X509Certificates.0.encoding`,
          `${service}.ServiceInformation.ServiceDigitalIdentity.X509Certificates.0.specRef`,
          `${service}.ServiceInformation.ServiceDigitalIdentity.PublicKeyValues.0.kty`,
          `${service}.ServiceHistory.0.ServiceDigitalIdentity`,
        ])
      )
    })

    it('should keep NextUpdate within 6 months of ListIssueDateTime with an offset, lowercase or leap second', () => {
      const errorPaths = (ListIssueDateTime: string, NextUpdate: string) => {
        const { payload: lote } = decodeJwt<any, LoteDocument>(EUPIDProvidersJWT)
        Object.assign(lote.LoTE.ListAndSchemeInformation, { ListIssueDateTime, NextUpdate })
        return validateLoteProfile(lote, LoteProfile.EuPidProvidersList).issues.map((issue) => issue.path.join('.'))
      }
      const tooLate = ['LoTE.ListAndSchemeInformation.NextUpdate']

      expect(errorPaths('2026-04-30T11:08:12Z', '2030-06-30T23:59:59Z')).toEqual(tooLate)
      expect(errorPaths('2026-04-30T11:08:12Z', '2030-06-30T23:59:60Z')).toEqual(tooLate)
      expect(errorPaths('2026-04-30t11:08:12z', '2030-07-01T01:59:60+02:00')).toEqual(tooLate)
      expect(errorPaths('2026-04-30T11:08:12Z', '2026-10-30t11:08:12z')).toEqual([])
      expect(errorPaths('2016-12-31T23:59:60Z', '2017-06-30T00:59:60+01:00')).toEqual([])
    })

    it('short-circuit errors when validating against wrong profile', () => {
      const { payload: lote } = decodeJwt(WRPACProvidersJWT)
      const result = validateLoteProfile(lote, [LoteProfile.EuPidProvidersList, LoteProfile.EuWalletProvidersList])

      expect(result.valid).toBe(false)
      expect(result.issues).toEqual(
        [LoteProfile.EuPidProvidersList, LoteProfile.EuWalletProvidersList].map((profile) => ({
          severity: 'error',
          code: LOTE_VALIDATION_CODES.UNEXPECTED_LOTE_TYPE,
          path: ['LoTE', 'ListAndSchemeInformation', 'LoTEType'],
          message: `Profile ${profile}: LoTEType must be ${LOTE_TYPES[profile]}`,
        }))
      )
    })

    it('only includes errors for matched LoteProfile', () => {
      const { payload: lote } = decodeJwt<any, LoteDocument>(WRPACProvidersJWT)

      lote.LoTE.ListAndSchemeInformation.StatusDeterminationApproach = 'invalid'

      const result = validateLoteProfile(lote, [
        LoteProfile.EuPidProvidersList,
        LoteProfile.EuWalletProvidersList,
        LoteProfile.EuWrpacProvidersList,
      ])

      expect(result.valid).toBe(false)
      expect(result.issues).toEqual([
        {
          severity: 'error',
          code: 'invalid_value',
          path: ['LoTE', 'ListAndSchemeInformation', 'StatusDeterminationApproach'],
          message:
            'Profile EuWrpacProvidersList: StatusDeterminationApproach must be http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU',
          context: { allowed: ['http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU'] },
        },
      ])
    })
    it('reports schema issues with numeric array indices', () => {
      const lote = createMinimalValidLote()
      lote.LoTE.TrustedEntitiesList = [{} as never]

      const result = validateLote(lote)

      expect(result.valid).toBe(false)
      expect(result.issues.length).toBeGreaterThan(0)
      for (const issue of result.issues) {
        expect(issue.path.slice(0, 3)).toEqual(['LoTE', 'TrustedEntitiesList', 0])
      }
    })
  })

  describe('compat mode and allowed territories', () => {
    const germanPid = () => decodeJwt<any, LoteDocument>(GermanPIDProvidersJWT).payload
    const germanSandboxWallet = () => decodeJwt<any, LoteDocument>(GermanSandboxWalletProvidersJWT).payload
    const service = 'LoTE.TrustedEntitiesList.0.TrustedEntityServices.0.ServiceInformation'

    it('should reject the German PID list in strict mode', () => {
      const paths = validateLoteProfile(germanPid(), LoteProfile.EuPidProvidersList).issues.map((issue) =>
        issue.path.join('.')
      )

      // The schema rejects the ServiceStatus, so the StatusStartingTime and SchemeTerritory rules don't run
      expect(paths).toContain(`${service}.ServiceStatus`)
      expect(paths).not.toContain(`${service}.StatusStartingTime`)
    })

    it('should accept the German lists in compat mode with territory DE', () => {
      const options = { mode: 'compat', allowedTerritories: ['DE'] } as const

      expect(validateLoteProfile(germanPid(), LoteProfile.EuPidProvidersList, options)).toMatchObject({
        valid: true,
        issues: [],
      })
      expect(validateLoteProfile(germanSandboxWallet(), LoteProfile.EuWalletProvidersList, options)).toMatchObject({
        valid: true,
        issues: [],
      })
    })

    it('should accept the Norwegian sandbox lists only in compat mode with territory NO', () => {
      for (const [jwt, profile] of [
        [NorwegianSandboxPIDProvidersJWT, LoteProfile.EuPidProvidersList],
        [NorwegianSandboxWRPACProvidersJWT, LoteProfile.EuWrpacProvidersList],
      ] as const) {
        const lote = decodeJwt(jwt).payload

        expect(validateLoteProfile(lote, profile).issues).toEqual([
          {
            severity: 'error',
            code: 'invalid_value',
            path: ['LoTE', 'ListAndSchemeInformation', 'SchemeTerritory'],
            message: `Profile ${profile}: SchemeTerritory must be EU`,
            context: { allowed: ['EU'] },
          },
        ])
        expect(validateLoteProfile(lote, profile, { mode: 'compat', allowedTerritories: ['NO'] })).toMatchObject({
          valid: true,
          issues: [],
        })
      }
    })

    // Expected to fail: its trusted entity has no TrustedEntityServices, which the TS 119 602 JSON schema requires
    it.fails('should accept the Norwegian sandbox Wallet Providers List in compat mode with territory NO', () => {
      const lote = decodeJwt(NorwegianSandboxWalletProvidersJWT).payload

      expect(
        validateLoteProfile(lote, LoteProfile.EuWalletProvidersList, { mode: 'compat', allowedTerritories: ['NO'] })
      ).toMatchObject({ valid: true, errors: [] })
    })

    it('should only accept the allowed territories, in compat mode only', () => {
      const issues = (lote: LoteDocument, allowedTerritories?: string[]) =>
        validateLoteProfile(lote, LoteProfile.EuPidProvidersList, { mode: 'compat', allowedTerritories }).issues.map(
          ({ path, message }) => ({ path: path.join('.'), message })
        )

      expect(issues(germanPid())).toContainEqual({
        path: 'LoTE.ListAndSchemeInformation.SchemeTerritory',
        message: 'Profile EuPidProvidersList: SchemeTerritory must be EU',
      })
      expect(issues(germanPid(), ['EU', 'NL'])).toContainEqual({
        path: 'LoTE.ListAndSchemeInformation.SchemeTerritory',
        message: 'Profile EuPidProvidersList: SchemeTerritory must be EU or NL',
      })
      expect(issues(germanPid(), ['EU', 'DE'])).toEqual([])
      expect(
        validateLoteProfile(decodeJwt(EUPIDProvidersJWT).payload, LoteProfile.EuPidProvidersList, {
          mode: 'compat',
          allowedTerritories: ['DE'],
        }).issues.map((issue) => issue.path.join('.'))
      ).toEqual(['LoTE.ListAndSchemeInformation.SchemeTerritory'])

      // TS 119 602 D to I: SchemeTerritory shall be EU
      expect(() =>
        validateLoteProfile(decodeJwt(EUPIDProvidersJWT).payload, LoteProfile.EuPidProvidersList, {
          // @ts-expect-error allowedTerritories is compat mode only
          allowedTerritories: ['DE'],
        })
      ).toThrow(new LoteError('allowedTerritories only applies in compat mode'))
    })

    it('should only accept the German notified status in compat mode, on a PID list', () => {
      const statusErrors = (ServiceStatus: string | undefined, profile = LoteProfile.EuPidProvidersList) => {
        const lote = profile === LoteProfile.EuPidProvidersList ? germanPid() : germanSandboxWallet()
        const information = lote.LoTE.TrustedEntitiesList?.[0]?.TrustedEntityServices[0]?.ServiceInformation
        if (!information) throw new Error('The German fixture has no service')
        information.ServiceStatus = ServiceStatus
        return validateLoteProfile(lote, profile, { mode: 'compat', allowedTerritories: ['DE'] }).issues.map(
          ({ path, message }) => ({ path: path.join('.'), message })
        )
      }
      const notified = 'http://uri.etsi.org/19602/PidProvidersList/SvcStatus/notified'

      expect(statusErrors(notified)).toEqual([])
      for (const status of [
        'http://uri.etsi.org/19602/PidProvidersList/SvcStatus/withdrawn',
        'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified',
      ]) {
        expect(statusErrors(status)).toEqual([
          {
            path: `${service}.ServiceStatus`,
            message: `Profile EuPidProvidersList: ServiceStatus must be one of the following: ${notified}`,
          },
        ])
      }
      expect(statusErrors(undefined)).toEqual([
        {
          path: `${service}.StatusStartingTime`,
          message: 'Profile EuPidProvidersList: StatusStartingTime must not be present',
        },
      ])
      expect(statusErrors(notified, LoteProfile.EuWalletProvidersList).map((issue) => issue.message)).toEqual([
        'Profile EuWalletProvidersList: ServiceStatus must not be present',
      ])
    })

    it('should accept a legal notice as localized URIs next to a policy only in compat mode', () => {
      const lote = germanSandboxWallet()

      expect(lote.LoTE.ListAndSchemeInformation.PolicyOrLegalNotice).toEqual([
        {
          LoTELegalNotice: [{ lang: 'de', uriValue: 'https://common.codes/impressum' }],
          LoTEPolicy: { lang: 'de', uriValue: 'https://common.codes/datenschutz' },
        },
      ])
      expect(validateLote(lote).issues.map((issue) => issue.path.join('.'))).toEqual([
        'LoTE.ListAndSchemeInformation.PolicyOrLegalNotice.0.LoTELegalNotice',
      ])
      expect(validateLote(lote, { mode: 'compat' })).toMatchObject({ valid: true, issues: [] })
    })

    it('should still reject an empty PolicyOrLegalNotice or an item with neither key in compat mode', () => {
      const lote = germanSandboxWallet()
      const paths = (PolicyOrLegalNotice: unknown) => {
        Object.assign(lote.LoTE.ListAndSchemeInformation, { PolicyOrLegalNotice })
        return validateLote(lote, { mode: 'compat' }).issues.map((issue) => issue.path.join('.'))
      }

      expect(paths([])).toEqual(['LoTE.ListAndSchemeInformation.PolicyOrLegalNotice'])
      expect(paths([{}])).toEqual(['LoTE.ListAndSchemeInformation.PolicyOrLegalNotice.0'])
    })
  })

  describe('typed results', () => {
    it('should return the validated document, typed by the mode', () => {
      const lote = decodeJwt<any, LoteDocument>(GermanSandboxWalletProvidersJWT).payload

      expectTypeOf(validateLote(lote)).toEqualTypeOf<ValidationResult<LoteDocument>>()
      expectTypeOf(validateLote(lote, { mode: 'compat' })).toEqualTypeOf<ValidationResult<CompatLoteDocument>>()
      // A compat document can carry a LoTELegalNotice that a strict one can't
      expectTypeOf<CompatLoteDocument>().not.toExtend<LoteDocument>()

      const result = validateLote(lote, { mode: 'compat' })
      if (!result.valid) throw new Error('The German sandbox list is valid in compat mode')
      expect(result.lote).toBe(lote)
    })

    it('should assert the type of the mode', () => {
      const lote: unknown = decodeJwt(GermanSandboxWalletProvidersJWT).payload

      expect(() => assertValidLote(lote)).toThrow(LoteError)
      assertValidLote(lote, { mode: 'compat' })
      expectTypeOf(lote).toEqualTypeOf<CompatLoteDocument>()
    })

    it('should type the document by the profile it matches', () => {
      const lote = decodeJwt<any, LoteDocument>(GermanPIDProvidersJWT).payload
      const result = validateLoteProfile(lote, [LoteProfile.EuPidProvidersList, LoteProfile.EuPubEaaProvidersList], {
        mode: 'compat',
        allowedTerritories: ['DE'],
      })
      if (!result.valid) throw new Error('The German PID list is valid in compat mode')
      expect(result.lote).toBe(lote)

      expect(result.loteType).toBe(LOTE_TYPES.EuPidProvidersList)

      const information = (lote: CompatLoteDocument) =>
        lote.LoTE.TrustedEntitiesList?.[0]?.TrustedEntityServices[0]?.ServiceInformation
      if (result.loteType === LOTE_TYPES.EuPidProvidersList) {
        expectTypeOf(result.lote).toEqualTypeOf<LoteProfileDocument<LoteProfile.EuPidProvidersList, 'compat'>>()
        expectTypeOf(
          result.lote.LoTE.TrustedEntitiesList?.[0]?.TrustedEntityServices[0]?.ServiceInformation.ServiceTypeIdentifier
        ).toEqualTypeOf<
          | 'http://uri.etsi.org/19602/SvcType/PID/Issuance'
          | 'http://uri.etsi.org/19602/SvcType/PID/Revocation'
          | undefined
        >()
        expect(information(result.lote)?.ServiceStatus).toBe(
          'http://uri.etsi.org/19602/PidProvidersList/SvcStatus/notified'
        )
        expectTypeOf(result).not.toHaveProperty('notifiedTrustedEntities')
      } else {
        expectTypeOf(result.loteType).toEqualTypeOf<typeof LOTE_TYPES.EuPubEaaProvidersList>()
        expectTypeOf(result.lote).toEqualTypeOf<LoteProfileDocument<LoteProfile.EuPubEaaProvidersList, 'compat'>>()
        expectTypeOf(result.notifiedTrustedEntities).toEqualTypeOf<
          NonNullable<LoteProfileDocument<LoteProfile.EuPubEaaProvidersList, 'compat'>['LoTE']['TrustedEntitiesList']>
        >()
      }

      expectTypeOf<LoteProfileDocument<LoteProfile.EuPidProvidersList>>().toExtend<LoteDocument>()
      expectTypeOf<LoteProfileDocument<LoteProfile.EuPidProvidersList, 'compat'>>().not.toExtend<LoteDocument>()

      type Status<D extends CompatLoteDocument> = NonNullable<
        D['LoTE']['TrustedEntitiesList']
      >[number]['TrustedEntityServices'][number]['ServiceInformation']['ServiceStatus']
      expectTypeOf<Status<LoteProfileDocument<LoteProfile.EuPidProvidersList>>>().toEqualTypeOf<undefined>()
      expectTypeOf<Status<LoteProfileDocument<LoteProfile.EuPidProvidersList, 'compat'>>>().toEqualTypeOf<
        'http://uri.etsi.org/19602/PidProvidersList/SvcStatus/notified' | undefined
      >()
      expectTypeOf<Status<LoteProfileDocument<LoteProfile.EuPubEaaProvidersList>>>().toEqualTypeOf<
        | 'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified'
        | 'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn'
      >()
    })
  })
})
