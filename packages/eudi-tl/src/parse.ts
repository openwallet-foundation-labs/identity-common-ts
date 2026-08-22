import { base64, hexEncode } from '@owf/identity-common'
import { SubjectKeyIdentifierExtension, X509Certificate } from '@peculiar/x509'
import { DOMParser, type Element } from '@xmldom/xmldom'
import { TrustedListParseException } from './trusted-list-exception'
import type {
  DigitalIdentity,
  ServiceHistoryInstance,
  TrustAnchor,
  TrustedList,
  TrustedListPointer,
  TrustedListService,
  TrustServiceProvider,
} from './types'
import { assertValidTrustedList, stripScheme } from './validate'

const TSL_NS = 'http://uri.etsi.org/02231/v2#'
const SIE_NS = 'http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#'

function descendants(el: Element, name: string, ns = TSL_NS): Element[] {
  return Array.from(el.getElementsByTagNameNS(ns, name))
}

function firstDescendant(el: Element, name: string, ns = TSL_NS): Element | undefined {
  return descendants(el, name, ns)[0]
}

function textOf(el: Element | undefined): string | undefined {
  const t = el?.textContent?.trim()
  return t ? t : undefined
}

/**
 * Localized `Name`: prefer the English entry, else the first, searched only
 * among the direct `Name` children of the given parent.
 */
function localizedName(parent: Element | undefined): string | undefined {
  if (!parent) return undefined
  const names = Array.from(parent.childNodes).filter(
    (n): n is Element => (n as Element).namespaceURI === TSL_NS && (n as Element).localName === 'Name'
  )
  if (names.length === 0) return undefined
  const en = names.find((n) => n.getAttribute('xml:lang') === 'en')
  return textOf(en ?? names[0])
}

/** Lowercase-hex SubjectKeyIdentifier from a certificate, best-effort. */
function skiFromCertificate(certBase64: string): string | undefined {
  try {
    const cert = new X509Certificate(certBase64)
    const ext = cert.getExtension(SubjectKeyIdentifierExtension)
    if (ext?.keyId) return ext.keyId.toLowerCase()
  } catch {
    // Malformed extensions (seen in some reference certificates) — caller
    // falls back to the published X509SKI element if any.
  }
  return undefined
}

/**
 * One {@link DigitalIdentity} per `ServiceDigitalIdentity`, merging its
 * `DigitalId` children (X509Certificate / X509SubjectName / X509SKI) — a
 * standard list may identify a service without embedding the full certificate.
 */
function parseDigitalIdentities(container: Element): DigitalIdentity[] {
  const identities: DigitalIdentity[] = []
  for (const sdi of descendants(container, 'ServiceDigitalIdentity')) {
    let certificate: string | undefined
    let subjectName: string | undefined
    let x509SkiHex: string | undefined
    for (const digitalId of descendants(sdi, 'DigitalId')) {
      certificate ??= textOf(firstDescendant(digitalId, 'X509Certificate'))?.replace(/\s/g, '')
      subjectName ??= textOf(firstDescendant(digitalId, 'X509SubjectName'))
      const ski = textOf(firstDescendant(digitalId, 'X509SKI'))
      if (ski && !x509SkiHex) {
        x509SkiHex = hexEncode(base64.decode(ski.replace(/\s/g, '')))
      }
    }
    if (!certificate && !subjectName && !x509SkiHex) continue
    identities.push({
      certificate,
      subjectName,
      subjectKeyIdentifier: certificate ? (skiFromCertificate(certificate) ?? x509SkiHex) : x509SkiHex,
    })
  }
  return identities
}

function parseQualifiers(serviceInfo: Element): string[] | undefined {
  const uris = descendants(serviceInfo, 'Qualifier', SIE_NS)
    .map((q) => q.getAttribute('uri') ?? '')
    .filter((u) => u.length > 0)
  return uris.length > 0 ? uris : undefined
}

function parseHistory(service: Element): ServiceHistoryInstance[] | undefined {
  const history: ServiceHistoryInstance[] = []
  for (const instance of descendants(service, 'ServiceHistoryInstance')) {
    const serviceStatus = textOf(firstDescendant(instance, 'ServiceStatus'))
    if (!serviceStatus) continue
    history.push({
      serviceTypeIdentifier: textOf(firstDescendant(instance, 'ServiceTypeIdentifier')),
      serviceStatus,
      statusStartingTime: textOf(firstDescendant(instance, 'StatusStartingTime')),
    })
  }
  return history.length > 0 ? history : undefined
}

function parsePointers(schemeInfo: Element): TrustedListPointer[] | undefined {
  const pointers: TrustedListPointer[] = []
  for (const pointer of descendants(schemeInfo, 'OtherTSLPointer')) {
    const location = textOf(firstDescendant(pointer, 'TSLLocation'))
    if (!location) continue
    pointers.push({
      location,
      tslType: textOf(firstDescendant(pointer, 'TSLType')),
      schemeTerritory: textOf(firstDescendant(pointer, 'SchemeTerritory')),
      // The pointer's own ServiceDigitalIdentities: the certificate(s) the
      // pointed-to list is signed with.
      digitalIdentities: parseDigitalIdentities(pointer),
    })
  }
  return pointers.length > 0 ? pointers : undefined
}

/**
 * Parse an ETSI TS 119 612 `TrustServiceStatusList` XML into a normalized
 * {@link TrustedList}. This does NOT verify the list signature — call
 * {@link verifyTrustedListSignature} first (or use {@link loadTrustedList}).
 */
export function parseTrustedList(xml: string): TrustedList {
  const doc = new DOMParser().parseFromString(xml, 'application/xml')
  const root: Element | null = doc.documentElement
  if (!root || root.localName !== 'TrustServiceStatusList') {
    throw new TrustedListParseException('Root element is not a TS 119 612 TrustServiceStatusList')
  }

  const schemeInfo = firstDescendant(root, 'SchemeInformation')
  const sequenceText = textOf(schemeInfo && firstDescendant(schemeInfo, 'TSLSequenceNumber'))
  const nextUpdate = schemeInfo && firstDescendant(schemeInfo, 'NextUpdate')

  const providers: TrustServiceProvider[] = []
  for (const tsp of descendants(root, 'TrustServiceProvider')) {
    const services: TrustedListService[] = []
    for (const service of descendants(tsp, 'TSPService')) {
      const info = firstDescendant(service, 'ServiceInformation')
      if (!info) continue
      const serviceTypeIdentifier = textOf(firstDescendant(info, 'ServiceTypeIdentifier'))
      const serviceStatus = textOf(firstDescendant(info, 'ServiceStatus'))
      if (!serviceTypeIdentifier || !serviceStatus) continue
      services.push({
        serviceTypeIdentifier,
        serviceStatus,
        serviceName: localizedName(firstDescendant(info, 'ServiceName')),
        digitalIdentities: parseDigitalIdentities(info),
        qualifiers: parseQualifiers(info),
        history: parseHistory(service),
      })
    }
    providers.push({
      name: localizedName(firstDescendant(tsp, 'TSPName')),
      services,
    })
  }

  // Validate the constructed object through the zod schema, so parsing is
  // schema-driven (the same approach @owf/eudi-lote uses for TS 119 602 JSON).
  return assertValidTrustedList({
    tslType: textOf(schemeInfo && firstDescendant(schemeInfo, 'TSLType')),
    schemeOperatorName: localizedName(schemeInfo && firstDescendant(schemeInfo, 'SchemeOperatorName')),
    sequenceNumber: sequenceText ? Number(sequenceText) : undefined,
    listIssueDateTime: textOf(schemeInfo && firstDescendant(schemeInfo, 'ListIssueDateTime')),
    nextUpdate: textOf(nextUpdate && firstDescendant(nextUpdate, 'dateTime')),
    providers,
    pointersToOtherLists: schemeInfo ? parsePointers(schemeInfo) : undefined,
  })
}

/** Selects `PointersToOtherTSL` entries in {@link getPointerSigningCertificates}. */
export interface TrustedListPointerFilter {
  /** `SchemeTerritory` of the pointed-to list (e.g. `ES`), case-insensitive. */
  schemeTerritory?: string
  /** `TSLType` of the pointed-to list, compared scheme-insensitively. */
  tslType?: string
  /** Exact `TSLLocation` URL of the pointed-to list. */
  location?: string
}

/**
 * The DER-encoded certificates a list publishes for the lists it points to —
 * i.e. the trust anchors with which those lists are signed, ready to be passed
 * as `trustAnchors` to `verifyTrustedListSignature`.
 *
 * This is the mechanism by which a trusted list distributes trust downwards: a
 * verifier that has established trust in one list (for the EU LOTL, by pinning
 * its signing certificates out of band) obtains the anchors of every list it
 * points to without pinning them individually.
 *
 * ```ts
 * const lotl = await loadTrustedList(lotlXml, { trustAnchors: getEuLotlTrustAnchors() })
 * const esAnchors = getPointerSigningCertificates(lotl, { schemeTerritory: 'ES' })
 * const esList = await loadTrustedList(esXml, { trustAnchors: esAnchors })
 * ```
 *
 * Passing `{ tslType: TSLType.EUlistofthelists }` returns the LOTL's own
 * currently published signing certificates (from its self-pointer), which is
 * how a deployment refreshes its pinned set as the scheme operator rotates keys.
 */
export function getPointerSigningCertificates(
  trustedList: TrustedList,
  filter: TrustedListPointerFilter = {}
): Uint8Array[] {
  const certificates: Uint8Array[] = []
  const seen = new Set<string>()
  for (const pointer of trustedList.pointersToOtherLists ?? []) {
    if (filter.location && pointer.location !== filter.location) continue
    if (filter.schemeTerritory && pointer.schemeTerritory?.toUpperCase() !== filter.schemeTerritory.toUpperCase()) {
      continue
    }
    if (filter.tslType && stripScheme(pointer.tslType) !== stripScheme(filter.tslType)) continue
    for (const identity of pointer.digitalIdentities) {
      if (!identity.certificate || seen.has(identity.certificate)) continue
      seen.add(identity.certificate)
      certificates.push(base64.decode(identity.certificate))
    }
  }
  return certificates
}

export interface TrustAnchorFilter {
  /**
   * When set, only include services whose `serviceStatus` is in this list
   * (e.g. `ACTIVE_SERVICE_STATUSES`). Withdrawn/deprecated services are
   * excluded.
   */
  serviceStatus?: string[]
  /** When set, only include services whose `serviceTypeIdentifier` matches. */
  serviceTypeIdentifier?: string[]
  /**
   * When true, only include anchors that embed an X.509 certificate (i.e. the
   * ones usable for certificate-chain validation). Defaults to false, which
   * also returns SubjectName/SKI-only identities (useful for AKI queries).
   */
  requireCertificate?: boolean
}

/**
 * Flatten a {@link TrustedList} into individual {@link TrustAnchor} entries —
 * the normalized unit consumed by certificate-chain validation and AKI
 * emission.
 */
export function getTrustAnchors(trustedList: TrustedList, filter: TrustAnchorFilter = {}): TrustAnchor[] {
  const anchors: TrustAnchor[] = []
  for (const provider of trustedList.providers) {
    for (const service of provider.services) {
      if (filter.serviceStatus && !filter.serviceStatus.includes(service.serviceStatus)) {
        continue
      }
      if (filter.serviceTypeIdentifier && !filter.serviceTypeIdentifier.includes(service.serviceTypeIdentifier)) {
        continue
      }
      for (const identity of service.digitalIdentities) {
        if (filter.requireCertificate && !identity.certificate) {
          continue
        }
        anchors.push({
          certificate: identity.certificate,
          subjectName: identity.subjectName,
          subjectKeyIdentifier: identity.subjectKeyIdentifier,
          serviceTypeIdentifier: service.serviceTypeIdentifier,
          serviceStatus: service.serviceStatus,
          providerName: provider.name,
        })
      }
    }
  }
  return anchors
}
