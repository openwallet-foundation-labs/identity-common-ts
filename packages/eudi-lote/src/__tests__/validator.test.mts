import { decodeJwt } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { assertValidLoTE, validateLoTE } from '../index'
import { LOTE_TYPES } from '../profiles'
import type { LoTEDocument } from '../types'
import { LoTEProfile, validateLoTEProfile } from '../validator'
import {
  EUPIDProvidersJWT,
  LP26PIDProvidersEmptyJWT,
  LP26WRPRCProvidersEmptyJWT,
  WalletProvidersJWT,
  WRPACProvidersJWT,
} from './fixtures.mjs'

describe('LoTE Validator', () => {
  const createMinimalValidLoTE = (): LoTEDocument => ({
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

  describe('validateLoTE', () => {
    it('should validate a minimal valid LoTE document', () => {
      const lote = createMinimalValidLoTE()
      const result = validateLoTE(lote)

      expect(result.valid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('should reject null', () => {
      const result = validateLoTE(null)

      expect(result.valid).toBe(false)
      expect(result.errors[0].message).toContain('expected object')
    })

    it('should reject undefined', () => {
      const result = validateLoTE(undefined)

      expect(result.valid).toBe(false)
    })

    it('should reject non-object values', () => {
      expect(validateLoTE('string').valid).toBe(false)
      expect(validateLoTE(123).valid).toBe(false)
      expect(validateLoTE([]).valid).toBe(false)
    })

    it('should require LoTE field', () => {
      const result = validateLoTE({})

      expect(result.valid).toBe(false)
      expect(result.errors.some((e) => e.path === 'LoTE')).toBe(true)
    })

    it('should require ListAndSchemeInformation', () => {
      const result = validateLoTE({ LoTE: {} })

      expect(result.valid).toBe(false)
      expect(result.errors.some((e) => e.path === 'LoTE.ListAndSchemeInformation')).toBe(true)
    })
  })

  describe('ListAndSchemeInformation validation', () => {
    it('should require LoTEVersionIdentifier', () => {
      const lote = createMinimalValidLoTE()
      // @ts-expect-error - Testing invalid input
      delete lote.LoTE.ListAndSchemeInformation.LoTEVersionIdentifier

      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
      expect(result.errors.some((e) => e.path === 'LoTE.ListAndSchemeInformation.LoTEVersionIdentifier')).toBe(true)
    })

    it('should require LoTESequenceNumber', () => {
      const lote = createMinimalValidLoTE()
      // @ts-expect-error - Testing invalid input
      delete lote.LoTE.ListAndSchemeInformation.LoTESequenceNumber

      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
      expect(result.errors.some((e) => e.path === 'LoTE.ListAndSchemeInformation.LoTESequenceNumber')).toBe(true)
    })

    it('should require SchemeOperatorName', () => {
      const lote = createMinimalValidLoTE()
      // @ts-expect-error - Testing invalid input
      delete lote.LoTE.ListAndSchemeInformation.SchemeOperatorName

      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
      expect(result.errors.some((e) => e.path === 'LoTE.ListAndSchemeInformation.SchemeOperatorName')).toBe(true)
    })

    it('should require non-empty SchemeOperatorName array', () => {
      const lote = createMinimalValidLoTE()
      lote.LoTE.ListAndSchemeInformation.SchemeOperatorName = []

      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
    })

    it('should require valid ListIssueDateTime', () => {
      const lote = createMinimalValidLoTE()
      lote.LoTE.ListAndSchemeInformation.ListIssueDateTime = 'invalid-date'

      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
      expect(result.errors.some((e) => e.path === 'LoTE.ListAndSchemeInformation.ListIssueDateTime')).toBe(true)
    })

    it('should require valid NextUpdate', () => {
      const lote = createMinimalValidLoTE()
      lote.LoTE.ListAndSchemeInformation.NextUpdate = 'not-a-date'

      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
      expect(result.errors.some((e) => e.path === 'LoTE.ListAndSchemeInformation.NextUpdate')).toBe(true)
    })

    it('should validate optional URI fields', () => {
      const lote = createMinimalValidLoTE()
      lote.LoTE.ListAndSchemeInformation.LoTEType = 'not-a-uri'
      lote.LoTE.ListAndSchemeInformation.DistributionPoints = ['not-a-uri']

      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
      expect(result.errors.some((e) => e.path === 'LoTE.ListAndSchemeInformation.LoTEType')).toBe(true)
      expect(result.errors.some((e) => e.path === 'LoTE.ListAndSchemeInformation.DistributionPoints.0')).toBe(true)
    })

    it('should validate SchemeTerritory is 2-character code', () => {
      const lote = createMinimalValidLoTE()
      lote.LoTE.ListAndSchemeInformation.SchemeTerritory = 'GERMANY'

      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
      expect(result.errors.some((e) => e.path === 'LoTE.ListAndSchemeInformation.SchemeTerritory')).toBe(true)
    })

    it('should accept valid 2-character SchemeTerritory', () => {
      const lote = createMinimalValidLoTE()
      lote.LoTE.ListAndSchemeInformation.SchemeTerritory = 'DE'

      const result = validateLoTE(lote)

      expect(result.valid).toBe(true)
    })
  })

  describe('PointersToOtherLoTE validation', () => {
    it('should validate PointersToOtherLoTE structure', () => {
      const lote = createMinimalValidLoTE()
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

      const result = validateLoTE(lote)

      expect(result.valid).toBe(true)
    })

    it('should reject invalid LoTELocation URI', () => {
      const lote = createMinimalValidLoTE()
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

      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
    })
  })

  describe('TrustedEntity validation', () => {
    it('should validate trusted entities with services', () => {
      const lote = createMinimalValidLoTE()
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

      const result = validateLoTE(lote)

      expect(result.valid).toBe(true)
    })

    it('should validate optional URI fields', () => {
      const lote = createMinimalValidLoTE()
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

      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
      expect(
        result.errors.some(
          (e) =>
            e.path ===
            'LoTE.TrustedEntitiesList.0.TrustedEntityServices.0.ServiceInformation.ServiceSupplyPoints.0.uriValue'
        )
      ).toBe(true)
    })

    it('should require at least one service per entity', () => {
      const lote = createMinimalValidLoTE()
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

      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
      expect(result.errors.some((e) => e.path.includes('TrustedEntityServices'))).toBe(true)
    })

    it('should require service name', () => {
      const lote = createMinimalValidLoTE()
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

      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
    })

    it('should require digital identity with at least one type', () => {
      const lote = createMinimalValidLoTE()
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

      const result = validateLoTE(lote)

      // The TS 119 602 JSON schema allows an empty ServiceDigitalIdentity; the EU profiles do not
      expect(result).toEqual({ valid: true, errors: [] })
    })
  })

  describe('ServiceHistory validation', () => {
    it('should validate service history entries', () => {
      const lote = createMinimalValidLoTE()
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

      const result = validateLoTE(lote)

      expect(result.valid).toBe(true)
    })

    it('should reject invalid service history status URI', () => {
      const lote = createMinimalValidLoTE()
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

      const result = validateLoTE(lote)

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
      const lote = createMinimalValidLoTE()
      return { LoTE: { ...lote.LoTE, TrustedEntitiesList: [entity] } }
    }

    const fullAddress = { lang: 'en', StreetAddress: '123 St', Locality: 'City', PostalCode: '12345', Country: 'DE' }

    it('should accept a list without TrustedEntitiesList', () => {
      const { LoTE } = createMinimalValidLoTE()
      const { TrustedEntitiesList: _, ...withoutEntities } = LoTE

      expect(validateLoTE({ LoTE: withoutEntities })).toEqual({ valid: true, errors: [] })
    })

    it('should accept a service supply point without ServiceType', () => {
      const lote = withEntity(createTrustedEntity(fullAddress, [{ uriValue: 'https://issuer.example.com/' }]))

      expect(validateLoTE(lote)).toEqual({ valid: true, errors: [] })
    })

    it('should still require uriValue on a service supply point', () => {
      const lote = withEntity(createTrustedEntity(fullAddress, [{ ServiceType: 'https://example.com/type' }]))
      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
      expect(result.errors.map((e) => e.path)).toEqual([
        'LoTE.TrustedEntitiesList.0.TrustedEntityServices.0.ServiceInformation.ServiceSupplyPoints.0.uriValue',
      ])
    })

    it('should accept a postal address without Locality and PostalCode', () => {
      const lote = withEntity(
        createTrustedEntity({ lang: 'en', StreetAddress: '123 St', Country: 'DE' }, [
          { uriValue: 'https://issuer.example.com/' },
        ])
      )

      expect(validateLoTE(lote)).toEqual({ valid: true, errors: [] })
    })

    it('should still require StreetAddress and Country on a postal address', () => {
      const lote = withEntity(
        createTrustedEntity({ lang: 'en', Locality: 'City', PostalCode: '12345' }, [
          { uriValue: 'https://issuer.example.com/' },
        ])
      )
      const result = validateLoTE(lote)

      expect(result.valid).toBe(false)
      expect(result.errors.map((e) => e.path)).toEqual([
        'LoTE.TrustedEntitiesList.0.TrustedEntityInformation.TEAddress.TEPostalAddress.0.StreetAddress',
        'LoTE.TrustedEntitiesList.0.TrustedEntityInformation.TEAddress.TEPostalAddress.0.Country',
      ])
    })

    it('should accept LoTELegalNotice as a plain string or a localized string', () => {
      const lote = createMinimalValidLoTE()
      lote.LoTE.ListAndSchemeInformation.PolicyOrLegalNotice = [
        { LoTELegalNotice: 'Legal notice' },
        { LoTELegalNotice: { lang: 'en', value: 'Legal notice' } },
      ]

      expect(validateLoTE(lote)).toEqual({ valid: true, errors: [] })
    })

    it('should reject an empty LoTELegalNotice object', () => {
      const lote = createMinimalValidLoTE()
      const result = validateLoTE({
        LoTE: {
          ...lote.LoTE,
          ListAndSchemeInformation: {
            ...lote.LoTE.ListAndSchemeInformation,
            PolicyOrLegalNotice: [{ LoTELegalNotice: {} }],
          },
        },
      })

      expect(result.valid).toBe(false)
      expect(result.errors.map((e) => e.path)).toContain(
        'LoTE.ListAndSchemeInformation.PolicyOrLegalNotice.0.LoTELegalNotice'
      )
    })

    const withPolicyOrLegalNotice = (items: unknown[]) => {
      const lote = createMinimalValidLoTE()
      return {
        LoTE: {
          ...lote.LoTE,
          ListAndSchemeInformation: { ...lote.LoTE.ListAndSchemeInformation, PolicyOrLegalNotice: items },
        },
      }
    }
    const policy = { LoTEPolicy: { lang: 'en', uriValue: 'https://example.com/policy' } }

    it('should accept an empty string legal notice, as the JSON schema does', () => {
      expect(validateLoTE(withPolicyOrLegalNotice([{ LoTELegalNotice: '' }]))).toEqual({ valid: true, errors: [] })
    })

    it('should reject a PolicyOrLegalNotice item with neither LoTEPolicy nor LoTELegalNotice', () => {
      const result = validateLoTE(withPolicyOrLegalNotice([{}]))

      expect(result.valid).toBe(false)
      expect(result.errors.map((e) => e.path)).toEqual(['LoTE.ListAndSchemeInformation.PolicyOrLegalNotice.0'])
    })

    it('should reject a PolicyOrLegalNotice whose every item has both LoTEPolicy and LoTELegalNotice', () => {
      const result = validateLoTE(withPolicyOrLegalNotice([{ ...policy, LoTELegalNotice: 'Notice' }]))

      expect(result.valid).toBe(false)
      expect(result.errors.map((e) => e.path)).toEqual(['LoTE.ListAndSchemeInformation.PolicyOrLegalNotice'])
    })

    it('should accept an item with both keys when another item has only one, as the oneOf does', () => {
      expect(validateLoTE(withPolicyOrLegalNotice([policy, { ...policy, LoTELegalNotice: 'Notice' }]))).toEqual({
        valid: true,
        errors: [],
      })
    })

    it('should reject an empty PolicyOrLegalNotice', () => {
      const result = validateLoTE(withPolicyOrLegalNotice([]))

      expect(result.errors.map((e) => e.path)).toEqual(['LoTE.ListAndSchemeInformation.PolicyOrLegalNotice'])
    })

    it('should reject policies and legal notices mixed in one PolicyOrLegalNotice', () => {
      const result = validateLoTE(withPolicyOrLegalNotice([policy, { LoTELegalNotice: 'Notice' }]))

      expect(result.valid).toBe(false)
      expect(result.errors.map((e) => e.path)).toEqual(['LoTE.ListAndSchemeInformation.PolicyOrLegalNotice.1'])
    })

    it('should accept date-times with an offset (RFC 3339)', () => {
      const lote = createMinimalValidLoTE()
      lote.LoTE.ListAndSchemeInformation.ListIssueDateTime = '2026-10-23T10:47:49+02:00'
      lote.LoTE.ListAndSchemeInformation.NextUpdate = '2027-04-23T10:47:49-05:30'

      expect(validateLoTE(lote)).toEqual({ valid: true, errors: [] })
    })

    it('should accept lowercase t and z and a leap second at 23:59:60 UTC (RFC 3339)', () => {
      const lote = createMinimalValidLoTE()
      lote.LoTE.ListAndSchemeInformation.ListIssueDateTime = '2016-12-31t23:59:60z'
      lote.LoTE.ListAndSchemeInformation.NextUpdate = '2017-01-01T00:59:60+01:00'

      expect(validateLoTE(lote)).toEqual({ valid: true, errors: [] })
    })

    it('should reject a leap second outside 23:59 UTC and an impossible date', () => {
      const lote = createMinimalValidLoTE()
      lote.LoTE.ListAndSchemeInformation.ListIssueDateTime = '2016-12-31T22:59:60Z'
      lote.LoTE.ListAndSchemeInformation.NextUpdate = '2026-02-29T00:00:00Z'

      expect(validateLoTE(lote).errors.map((e) => e.path)).toEqual([
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

      expect(validateLoTE(lote)).toEqual({ valid: true, errors: [] })
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

      expect(validateLoTE(lote).errors.map((e) => e.path)).toEqual([
        'LoTE.TrustedEntitiesList.0.TrustedEntityServices.0.ServiceInformation.ServiceDigitalIdentity.X509Certificates.0.encoding',
      ])
    })
  })

  describe('assertValidLoTE', () => {
    it('should not throw for valid LoTE document', () => {
      const lote = createMinimalValidLoTE()

      expect(() => assertValidLoTE(lote)).not.toThrow()
    })

    it('should throw for invalid LoTE document', () => {
      expect(() => assertValidLoTE({})).toThrow('Invalid LoTE document')
    })

    it('should include error details in thrown error', () => {
      try {
        assertValidLoTE({ LoTE: {} })
        expect.fail('Should have thrown')
      } catch (error) {
        expect((error as Error).message).toContain('ListAndSchemeInformation')
      }
    })
  })

  describe('validateLoTEProfile', () => {
    it('should validate against EUPIDProvidersList profile', () => {
      const { payload: lote } = decodeJwt(EUPIDProvidersJWT)
      const result = validateLoTEProfile(lote, LoTEProfile.EUPIDProvidersList)

      expect(result.valid).toBe(true)
    })

    it('should validate against EUWalletProvidersList profile', () => {
      const { payload: lote } = decodeJwt(WalletProvidersJWT)
      const result = validateLoTEProfile(lote, LoTEProfile.EUWalletProvidersList)

      expect(result.valid).toBe(true)
    })

    it('should validate against EUWRPACProvidersList profile', () => {
      const { payload: lote } = decodeJwt(WRPACProvidersJWT)
      const result = validateLoTEProfile(lote, LoTEProfile.EUWRPACProvidersList)

      expect(result.valid).toBe(true)
    })

    it('should validate an EC list without trusted entities against EUPIDProvidersList profile', () => {
      const { payload: lote } = decodeJwt<any, LoTEDocument>(LP26PIDProvidersEmptyJWT)

      expect(lote.LoTE.TrustedEntitiesList).toBeUndefined()
      expect(validateLoTE(lote)).toEqual({ valid: true, errors: [] })
      expect(validateLoTEProfile(lote, LoTEProfile.EUPIDProvidersList)).toEqual({ valid: true, errors: [] })
    })

    it('should validate an EC list with a plain string legal notice against EUWRPRCProvidersList profile', () => {
      const { payload: lote } = decodeJwt<any, LoTEDocument>(LP26WRPRCProvidersEmptyJWT)

      expect(lote.LoTE.ListAndSchemeInformation.PolicyOrLegalNotice).toEqual([{ LoTELegalNotice: 'Legal notice' }])
      expect(validateLoTE(lote)).toEqual({ valid: true, errors: [] })
      expect(validateLoTEProfile(lote, LoTEProfile.EUWRPRCProvidersList)).toEqual({ valid: true, errors: [] })
    })

    /** The EC WRPAC list, turned into a list of another EU profile by its URIs */
    const asProfile = (kind: 'EAA' | 'PubEAA') => {
      const { payload } = decodeJwt<any, LoTEDocument>(WRPACProvidersJWT)
      const json = JSON.stringify(payload)
        .replace(/LoTEType\/EUWRPACProvidersList/g, `LoTEType/EU${kind}ProvidersList`)
        .replace(/WRPACProvidersList\//g, `${kind}ProvidersList/`)
        .replace(/ListOfTrustedEntities\/WRPACProvider\//g, `ListOfTrustedEntities/${kind}Provider/`)
        .replace(/SvcType\/WRPAC\//g, `SvcType/${kind}/`)
      const lote = JSON.parse(json) as LoTEDocument
      if (kind === 'PubEAA') lote.LoTE.ListAndSchemeInformation.HistoricalInformationPeriod = 65535
      return lote
    }

    it('should validate a list against the EUEAAProvidersList profile', () => {
      const lote = asProfile('EAA')

      expect(lote.LoTE.ListAndSchemeInformation.LoTEType).toBe(LOTE_TYPES.EUEAAProvidersList)
      expect(validateLoTEProfile(lote, LoTEProfile.EUEAAProvidersList)).toEqual({ valid: true, errors: [] })
    })

    it('should validate a list against the EUPubEAAProvidersList profile', () => {
      const lote = asProfile('PubEAA')

      expect(lote.LoTE.ListAndSchemeInformation.LoTEType).toBe(LOTE_TYPES.EUPubEAAProvidersList)
      expect(validateLoTEProfile(lote, LoTEProfile.EUPubEAAProvidersList)).toEqual({ valid: true, errors: [] })
    })

    it('should keep requiring a 2-letter country and a digital identity in the EU profiles', () => {
      const { payload: lote } = decodeJwt<any, LoTEDocument>(WRPACProvidersJWT)
      const entity = lote.LoTE.TrustedEntitiesList?.[0]
      const address = entity?.TrustedEntityInformation.TEAddress.TEPostalAddress[0]
      const firstService = entity?.TrustedEntityServices[0]
      if (!address || !firstService) throw new Error('The WRPAC fixture has no entity with an address and a service')
      address.Country = 'Germany'
      firstService.ServiceInformation.ServiceDigitalIdentity = {}

      expect(validateLoTE(lote)).toEqual({ valid: true, errors: [] })
      const result = validateLoTEProfile(lote, LoTEProfile.EUWRPACProvidersList)
      expect(result.valid).toBe(false)
      expect(result.errors.map((e) => e.path)).toEqual([
        'LoTEType',
        'LoTE.TrustedEntitiesList.0.TrustedEntityInformation.TEAddress.TEPostalAddress.0.Country',
        'LoTE.TrustedEntitiesList.0.TrustedEntityServices.0.ServiceInformation.ServiceDigitalIdentity',
      ])
    })

    it('should keep the rules the base schema used to apply in the EU profiles', () => {
      const { payload: lote } = decodeJwt<any, LoTEDocument>(WRPACProvidersJWT)
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

      expect(validateLoTE(lote)).toEqual({ valid: true, errors: [] })
      const paths = validateLoTEProfile(lote, LoTEProfile.EUWRPACProvidersList).errors.map((e) => e.path)
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

    it('short-circuit errors when validating against wrong profile', () => {
      const { payload: lote } = decodeJwt(WRPACProvidersJWT)
      const result = validateLoTEProfile(lote, [LoTEProfile.EUPIDProvidersList, LoTEProfile.EUWalletProvidersList])

      expect(result.valid).toBe(false)
      expect(result.errors).toEqual([
        {
          message: 'Document does not match any of the specified profiles: EUPIDProvidersList, EUWalletProvidersList',
          path: 'LoTEType',
        },
        {
          message: 'Profile EUPIDProvidersList: LoTEType must be http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList',
          path: 'LoTE.ListAndSchemeInformation.LoTEType',
        },
        {
          message:
            'Profile EUWalletProvidersList: LoTEType must be http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList',
          path: 'LoTE.ListAndSchemeInformation.LoTEType',
        },
      ])
    })

    it('only includes errors for matched LoTEProfile', () => {
      const { payload: lote } = decodeJwt<any, LoTEDocument>(WRPACProvidersJWT)

      lote.LoTE.ListAndSchemeInformation.StatusDeterminationApproach = 'invalid'

      const result = validateLoTEProfile(lote, [
        LoTEProfile.EUPIDProvidersList,
        LoTEProfile.EUWalletProvidersList,
        LoTEProfile.EUWRPACProvidersList,
      ])

      expect(result.valid).toBe(false)
      expect(result.errors).toEqual([
        {
          message: 'Document does not match profile EUWRPACProvidersList',
          path: 'LoTEType',
        },
        {
          message: 'Profile EUWRPACProvidersList: Invalid URL',
          path: 'LoTE.ListAndSchemeInformation.StatusDeterminationApproach',
        },
        {
          message:
            'Profile EUWRPACProvidersList: StatusDeterminationApproach must be http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU',
          path: 'LoTE.ListAndSchemeInformation.StatusDeterminationApproach',
        },
      ])
    })
  })
})
