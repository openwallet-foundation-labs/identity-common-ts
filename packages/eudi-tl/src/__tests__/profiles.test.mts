import { describe, expect, it } from 'vitest'
import { ServiceStatus, ServiceType, TrustedListProfiles, TSLType, validateTrustedListProfile } from '../index'

/**
 * The shipped {@link TrustedListProfiles} are plain {@link ProfileRule}s fed to
 * the same profile-agnostic engine. These use synthetic, minimal lists (no real
 * trust list involved) mirroring how each ecosystem shapes its entries.
 */
const service = (serviceTypeIdentifier: string, serviceStatus: string) => ({
  serviceTypeIdentifier,
  serviceStatus,
  digitalIdentities: [],
})

describe('TrustedListProfiles.euLotl', () => {
  it('accepts a List of Trusted Lists with no TSP services', () => {
    const result = validateTrustedListProfile(
      { tslType: TSLType.EUlistofthelists, providers: [] },
      TrustedListProfiles.euLotl
    )
    expect(result.valid).toBe(true)
  })

  it('rejects a generic national list (wrong TSLType)', () => {
    const result = validateTrustedListProfile({ tslType: TSLType.EUgeneric, providers: [] }, TrustedListProfiles.euLotl)
    expect(result.valid).toBe(false)
    expect(result.errors.some((e) => e.path === 'tslType')).toBe(true)
  })
})

describe('TrustedListProfiles.euGeneric', () => {
  it('accepts a national list mixing qualified service types and statuses', () => {
    const result = validateTrustedListProfile(
      {
        tslType: TSLType.EUgeneric,
        providers: [
          { services: [service(ServiceType.CA_QC, ServiceStatus.Granted)] },
          // National lists retain withdrawn/ceased services for history.
          { services: [service(ServiceType.TSA_QTST, ServiceStatus.Withdrawn)] },
          { services: [service(ServiceType.PSES_Q, ServiceStatus.SupervisionCeased)] },
        ],
      },
      TrustedListProfiles.euGeneric
    )
    expect(result.valid).toBe(true)
  })

  it('rejects a non-standard service type', () => {
    const result = validateTrustedListProfile(
      {
        tslType: TSLType.EUgeneric,
        providers: [{ services: [service('http://example.org/Svctype/Custom', ServiceStatus.Granted)] }],
      },
      TrustedListProfiles.euGeneric
    )
    expect(result.valid).toBe(false)
  })
})

describe('TrustedListProfiles.ageVerification', () => {
  const AV_TSL_TYPE = 'https://trust.tech.ec.europa.eu/lists/age-verification/tsl-type'
  const AV_PAA = 'http://trust.tech.ec.europa.eu/lists/age-verification/service-type/paa'
  const AV_RECOGNIZED = 'http://trust.tech.ec.europa.eu/lists/age-verification/service-status/recognized'

  it('accepts an AV list', () => {
    const result = validateTrustedListProfile(
      { tslType: AV_TSL_TYPE, providers: [{ services: [service(AV_PAA, AV_RECOGNIZED)] }] },
      TrustedListProfiles.ageVerification
    )
    expect(result.valid).toBe(true)
  })

  it('compares scheme-insensitively (production uses http)', () => {
    const result = validateTrustedListProfile(
      {
        tslType: 'http://trust.tech.ec.europa.eu/lists/age-verification/tsl-type',
        providers: [{ services: [service(AV_PAA, AV_RECOGNIZED)] }],
      },
      TrustedListProfiles.ageVerification
    )
    expect(result.valid).toBe(true)
  })

  it('rejects a standard eIDAS service type under the AV profile', () => {
    const result = validateTrustedListProfile(
      { tslType: AV_TSL_TYPE, providers: [{ services: [service(ServiceType.CA_QC, AV_RECOGNIZED)] }] },
      TrustedListProfiles.ageVerification
    )
    expect(result.valid).toBe(false)
  })
})
