import { base64, ValidationError } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import {
  ACTIVE_SERVICE_STATUSES,
  assertValidTrustedList,
  getPointerSigningCertificates,
  getTrustAnchors,
  parseTrustedList,
  ServiceStatus,
  ServiceType,
  TrustedListParseError,
  TrustedListValidationError,
  TslType,
  validateTrustedList,
} from '../index'
import {
  CA_CERT_SKI_HEX,
  LEGACY_SKI_HEX,
  LOTL_POINTER_CERT_BASE64,
  NATIONAL_POINTER_CERT_BASE64,
  UNSIGNED_TSL_XML,
} from './fixtures.mjs'

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

    expect(tl.tslType).toBe(TslType.EUgeneric)
    expect(tl.schemeOperatorName).toBe('Test Scheme Operator') // 'en' entry preferred
    // the list's own territory, not the one of a pointer
    expect(tl.schemeTerritory).toBe('ES')
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

    // PointersToOtherTSL → the EU List of Trusted Lists and a national list,
    // each publishing the certificate the pointed-to list is signed with.
    expect(tl.pointersToOtherLists).toHaveLength(2)
    expect(tl.pointersToOtherLists?.[0]).toEqual({
      location: 'https://ec.europa.eu/tools/lotl/eu-lotl.xml',
      tslType: TslType.EUlistofthelists,
      schemeTerritory: 'EU',
      digitalIdentities: [
        {
          certificate: LOTL_POINTER_CERT_BASE64,
          subjectName: undefined,
          subjectKeyIdentifier: expect.any(String),
        },
      ],
    })
    expect(tl.pointersToOtherLists?.[1].schemeTerritory).toBe('DE')

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
    expect(() => parseTrustedList('<root/>')).toThrow(TrustedListParseError)
  })

  it('throws the issues of a list that does not conform, as a validation error', () => {
    let error: unknown
    try {
      assertValidTrustedList({})
    } catch (thrown) {
      error = thrown
    }
    expect(error).toBeInstanceOf(TrustedListValidationError)
    expect(error).toBeInstanceOf(ValidationError)
    expect((error as TrustedListValidationError).issues).toEqual(validateTrustedList({}).issues)
  })
})

/**
 * A list distributes the trust anchors of the lists it points to: the EU LOTL
 * publishes, for every national list, the certificate(s) of its scheme
 * operator. These are what a verifier passes as `trustAnchors` when it then
 * fetches that national list.
 */
describe('getPointerSigningCertificates', () => {
  it('returns every pointer certificate when unfiltered', () => {
    const tl = parseTrustedList(UNSIGNED_TSL_XML)
    const certificates = getPointerSigningCertificates(tl)
    expect(certificates).toHaveLength(2)
    expect(certificates[0]).toEqual(base64.decode(LOTL_POINTER_CERT_BASE64))
  })

  it('selects the anchors of a single pointed-to list by territory', () => {
    const tl = parseTrustedList(UNSIGNED_TSL_XML)
    const de = getPointerSigningCertificates(tl, { schemeTerritory: 'de' })
    expect(de).toEqual([base64.decode(NATIONAL_POINTER_CERT_BASE64)])
  })

  it('selects the list-of-lists self-pointer, i.e. the refreshed LOTL signer set', () => {
    const tl = parseTrustedList(UNSIGNED_TSL_XML)
    // Scheme-insensitive TSLType match, as deployed lists use both http and https.
    const lotl = getPointerSigningCertificates(tl, {
      tslType: 'https://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists',
    })
    expect(lotl).toEqual([base64.decode(LOTL_POINTER_CERT_BASE64)])
  })

  it('returns nothing for a pointer that is not present', () => {
    const tl = parseTrustedList(UNSIGNED_TSL_XML)
    expect(getPointerSigningCertificates(tl, { schemeTerritory: 'FR' })).toEqual([])
    expect(getPointerSigningCertificates(tl, { location: 'https://example.test/unknown.xml' })).toEqual([])
  })
})

/**
 * ETSI TS 119 612 clause 5.3.13: a pointer advertises the MIME type of the pointed-to list. The EU LOTL points to
 * the XML list (`application/vnd.etsi.tsl+xml`) and, for some territories, to a PDF of it (`application/pdf`).
 */
describe('pointer MimeType', () => {
  const XML_MIME_TYPE = 'application/vnd.etsi.tsl+xml'
  const pointer = (territory: string, certificate: string, mimeType: string) => `
      <tsl:OtherTSLPointer>
        <tsl:ServiceDigitalIdentities>
          <tsl:ServiceDigitalIdentity>
            <tsl:DigitalId><tsl:X509Certificate>${certificate}</tsl:X509Certificate></tsl:DigitalId>
          </tsl:ServiceDigitalIdentity>
        </tsl:ServiceDigitalIdentities>
        <tsl:TSLLocation>https://example.test/tsl-${territory.toLowerCase()}-${certificate.length}.xml</tsl:TSLLocation>
        <tsl:AdditionalInformation>
          <tsl:OtherInformation><tsl:TSLType>${TslType.EUgeneric}</tsl:TSLType></tsl:OtherInformation>
          <tsl:OtherInformation><tsl:SchemeTerritory>${territory}</tsl:SchemeTerritory></tsl:OtherInformation>
          ${mimeType}
        </tsl:AdditionalInformation>
      </tsl:OtherTSLPointer>`
  // The prefix is free: the live EU LOTL binds the namespace to `ns3`
  const LIST_XML = `<?xml version="1.0" encoding="UTF-8"?>
<tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#" xmlns:tslx="http://uri.etsi.org/02231/v2/additionaltypes#">
  <tsl:SchemeInformation>
    <tsl:TSLType>${TslType.EUlistofthelists}</tsl:TSLType>
    <tsl:SchemeTerritory>EU</tsl:SchemeTerritory>
    <tsl:PointersToOtherTSL>
      ${pointer('DE', NATIONAL_POINTER_CERT_BASE64, `<tsl:OtherInformation><tslx:MimeType>${XML_MIME_TYPE}</tslx:MimeType></tsl:OtherInformation>`)}
      ${pointer('DE', LOTL_POINTER_CERT_BASE64, '<tsl:OtherInformation><ns3:MimeType xmlns:ns3="http://uri.etsi.org/02231/v2/additionaltypes#"> application/pdf </ns3:MimeType></tsl:OtherInformation>')}
      ${pointer('FR', NATIONAL_POINTER_CERT_BASE64, '<tsl:OtherInformation><tslx:MimeType> </tslx:MimeType></tsl:OtherInformation>')}
      ${pointer('IT', LOTL_POINTER_CERT_BASE64, '')}
    </tsl:PointersToOtherTSL>
  </tsl:SchemeInformation>
  <tsl:TrustServiceProviderList/>
</tsl:TrustServiceStatusList>`

  it('reads the trimmed MimeType of each pointer, and none when it is empty or missing', () => {
    const tl = parseTrustedList(LIST_XML)
    expect(validateTrustedList(tl).valid).toBe(true)
    expect(tl.pointersToOtherLists?.map((p) => [p.schemeTerritory, p.mimeType])).toEqual([
      ['DE', XML_MIME_TYPE],
      ['DE', 'application/pdf'],
      ['FR', undefined],
      ['IT', undefined],
    ])
  })

  it('selects the pointers to XML lists, case-insensitively', () => {
    const tl = parseTrustedList(LIST_XML)
    const xml = [base64.decode(NATIONAL_POINTER_CERT_BASE64)]
    expect(getPointerSigningCertificates(tl, { mimeType: XML_MIME_TYPE })).toEqual(xml)
    expect(getPointerSigningCertificates(tl, { mimeType: 'Application/VND.ETSI.TSL+XML' })).toEqual(xml)
    expect(getPointerSigningCertificates(tl, { schemeTerritory: 'DE', mimeType: XML_MIME_TYPE })).toEqual(xml)
    expect(getPointerSigningCertificates(tl, { mimeType: 'application/pdf' })).toEqual([
      base64.decode(LOTL_POINTER_CERT_BASE64),
    ])
  })

  it('does not select a pointer without a MimeType when filtering by it', () => {
    const tl = parseTrustedList(LIST_XML)
    expect(getPointerSigningCertificates(tl, { schemeTerritory: 'FR', mimeType: XML_MIME_TYPE })).toEqual([])
    expect(getPointerSigningCertificates(tl, { schemeTerritory: 'IT', mimeType: XML_MIME_TYPE })).toEqual([])
    // Without the filter, they are selected as before
    expect(getPointerSigningCertificates(tl, { schemeTerritory: 'IT' })).toEqual([
      base64.decode(LOTL_POINTER_CERT_BASE64),
    ])
  })

  it('rejects an empty MimeType in the schema', () => {
    const result = validateTrustedList({
      providers: [],
      pointersToOtherLists: [{ location: 'https://example.test/tsl.xml', mimeType: '', digitalIdentities: [] }],
    })
    expect(result.valid).toBe(false)
    expect(result.issues[0].path).toEqual(['pointersToOtherLists', 0, 'mimeType'])
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
