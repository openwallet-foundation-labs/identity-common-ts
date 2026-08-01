import { describe, expect, it } from 'vitest'
import {
  ACTIVE_SERVICE_STATUSES,
  getTrustAnchors,
  parseTrustedList,
  ServiceStatus,
  ServiceType,
  TrustedListParseException,
  TSLType,
  validateTrustedList,
} from '../index'
import { CA_CERT_SKI_HEX, LEGACY_SKI_HEX, UNSIGNED_TSL_XML } from './fixtures.mjs'

/**
 * The library must handle a standard ETSI TS 119 612 eIDAS-style list. The
 * fixture is a small synthetic list using the standard `TSLType/EUgeneric`,
 * `TrstSvc/Svctype/*` types and `Svcstatus/*` statuses, with ServiceHistory,
 * qualifiers, and a LOTL pointer. Parsing does not require a signature.
 */
describe('parseTrustedList', () => {
  it('parses the standard structure and passes schema validation', () => {
    const tl = parseTrustedList(UNSIGNED_TSL_XML)
    expect(validateTrustedList(tl).valid).toBe(true)

    expect(tl.tslType).toBe(TSLType.EUgeneric)
    expect(tl.schemeOperatorName).toBe('Test Scheme Operator') // 'en' entry preferred
    expect(tl.sequenceNumber).toBe(42)
    expect(tl.listIssueDateTime).toBe('2025-01-15T00:00:00Z')
    expect(tl.nextUpdate).toBe('2025-07-15T00:00:00Z')

    expect(tl.providers.map((p) => p.name)).toEqual(['Test Qualified CA S.A.', 'Test Timestamping Provider'])
    const services = tl.providers.flatMap((p) => p.services)
    expect(services).toHaveLength(3)

    // Standard ETSI service types and statuses are read as-is.
    const types = new Set(services.map((s) => s.serviceTypeIdentifier))
    expect(types).toEqual(new Set([ServiceType.CA_QC, ServiceType.TSA_QTST]))
    const statuses = new Set(services.map((s) => s.serviceStatus))
    expect(statuses).toEqual(new Set([ServiceStatus.Granted, ServiceStatus.Withdrawn]))
  })

  it('merges DigitalId entries and derives the SubjectKeyIdentifier', () => {
    const tl = parseTrustedList(UNSIGNED_TSL_XML)
    const [qcCa, legacyCa] = tl.providers[0].services

    // Certificate + subject name + SKI merged into one identity; the SKI is
    // derived from the embedded certificate.
    expect(qcCa.digitalIdentities).toHaveLength(1)
    expect(qcCa.digitalIdentities[0].certificate).toBeDefined()
    expect(qcCa.digitalIdentities[0].subjectName).toContain('Test QC CA')
    expect(qcCa.digitalIdentities[0].subjectKeyIdentifier).toBe(CA_CERT_SKI_HEX)

    // Without an embedded certificate, the published X509SKI element is used.
    expect(legacyCa.digitalIdentities[0].certificate).toBeUndefined()
    expect(legacyCa.digitalIdentities[0].subjectKeyIdentifier).toBe(LEGACY_SKI_HEX)
  })

  it('captures the LOTL pointer, service qualifiers and service history', () => {
    const tl = parseTrustedList(UNSIGNED_TSL_XML)

    // PointersToOtherTSL → the EU List of Trusted Lists.
    expect(tl.pointersToOtherLists).toHaveLength(1)
    expect(tl.pointersToOtherLists?.[0]).toEqual({
      location: 'https://ec.europa.eu/tools/lotl/eu-lotl.xml',
      tslType: TSLType.EUlistofthelists,
      schemeTerritory: 'EU',
    })

    const [qcCa] = tl.providers[0].services
    // Qualifications (e.g. QCStatements) are captured as qualifier URIs.
    expect(qcCa.qualifiers).toEqual([
      'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD',
      'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement',
    ])
    // ServiceHistory instances are captured.
    expect(qcCa.history).toEqual([
      {
        serviceTypeIdentifier: ServiceType.CA_QC,
        serviceStatus: ServiceStatus.UnderSupervision,
        statusStartingTime: '2016-07-01T00:00:00Z',
      },
    ])
  })

  it('rejects XML whose root is not a TrustServiceStatusList', () => {
    expect(() => parseTrustedList('<root/>')).toThrow(TrustedListParseException)
  })
})

describe('getTrustAnchors', () => {
  it('filters to active anchors and excludes withdrawn ones', () => {
    const tl = parseTrustedList(UNSIGNED_TSL_XML)
    const all = getTrustAnchors(tl)
    expect(all).toHaveLength(3)

    const active = getTrustAnchors(tl, { serviceStatus: ACTIVE_SERVICE_STATUSES })
    expect(active).toHaveLength(2)
    expect(active.every((a) => ACTIVE_SERVICE_STATUSES.includes(a.serviceStatus))).toBe(true)
    // Anchors expose SubjectKeyIdentifiers for AKI use.
    expect(active.every((a) => !!a.subjectKeyIdentifier)).toBe(true)
  })

  it('filters by service type and can require an embedded certificate', () => {
    const tl = parseTrustedList(UNSIGNED_TSL_XML)

    const timestamping = getTrustAnchors(tl, { serviceTypeIdentifier: [ServiceType.TSA_QTST] })
    expect(timestamping).toHaveLength(1)
    expect(timestamping[0].providerName).toBe('Test Timestamping Provider')

    // The withdrawn service publishes no certificate, so requiring one drops it.
    const withCertificate = getTrustAnchors(tl, { requireCertificate: true })
    expect(withCertificate).toHaveLength(2)
    expect(withCertificate.every((a) => !!a.certificate)).toBe(true)
  })
})
