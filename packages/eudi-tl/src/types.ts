import { z } from 'zod'

/**
 * A service's digital identity (TS 119 612 `ServiceDigitalIdentity`): the
 * `DigitalId` children (X509Certificate, X509SubjectName, X509SKI) that describe
 * one entity are merged here. A standard list may identify a service by subject
 * name and/or key identifier without embedding the full certificate.
 */
export const zDigitalIdentity = z.object({
  /** base64-encoded DER of the certificate, when embedded (`X509Certificate`). */
  certificate: z.string().optional(),
  /** `X509SubjectName`, when present. */
  subjectName: z.string().optional(),
  /**
   * Lowercase-hex SubjectKeyIdentifier — derived from the certificate when one
   * is embedded, otherwise from the `X509SKI` element. This is the value a
   * verifier sends to a wallet as an `aki` trusted authority (HAIP).
   */
  subjectKeyIdentifier: z.string().optional(),
})
export type DigitalIdentity = z.infer<typeof zDigitalIdentity>

/** A past status entry for a service (`ServiceHistoryInstance`). */
export const zServiceHistoryInstance = z.object({
  serviceTypeIdentifier: z.string().optional(),
  serviceStatus: z.string(),
  statusStartingTime: z.string().optional(),
})
export type ServiceHistoryInstance = z.infer<typeof zServiceHistoryInstance>

/**
 * A trust service (TSPService) entry: its type, status, digital identities,
 * qualifiers, and status history.
 */
export const zTrustedListService = z.object({
  /** `ServiceTypeIdentifier` URI. */
  serviceTypeIdentifier: z.string(),
  /** Current `ServiceStatus` URI. */
  serviceStatus: z.string(),
  /** Human-readable service name, if present. */
  serviceName: z.string().optional(),
  /** One entry per `ServiceDigitalIdentity`. */
  digitalIdentities: z.array(zDigitalIdentity),
  /** Qualifier URIs from `Qualifications/QualificationElement/Qualifiers`. */
  qualifiers: z.array(z.string()).optional(),
  /** Prior status entries from `ServiceHistory`. */
  history: z.array(zServiceHistoryInstance).optional(),
})
export type TrustedListService = z.infer<typeof zTrustedListService>

/** A Trust Service Provider (TSP) and the services it operates. */
export const zTrustServiceProvider = z.object({
  name: z.string().optional(),
  services: z.array(zTrustedListService),
})
export type TrustServiceProvider = z.infer<typeof zTrustServiceProvider>

/** A pointer to another trusted list (`OtherTSLPointer`), e.g. the EU LOTL. */
export const zTrustedListPointer = z.object({
  /** `TSLLocation` URL. */
  location: z.string(),
  /** Pointed-to list `TSLType`, when advertised. */
  tslType: z.string().optional(),
  /** `SchemeTerritory` (country code), when advertised. */
  schemeTerritory: z.string().optional(),
  /**
   * The pointer's `ServiceDigitalIdentities`: the certificates with which the
   * pointed-to list is signed. This is how a list distributes the trust anchors
   * of the lists it points to — the EU LOTL carries, for every national list,
   * the certificate(s) of its scheme operator, so a verifier that trusts the
   * LOTL does not need to pin each national list separately.
   */
  digitalIdentities: z.array(zDigitalIdentity).default([]),
})
export type TrustedListPointer = z.infer<typeof zTrustedListPointer>

/** A parsed ETSI TS 119 612 Trusted List (`TrustServiceStatusList`). */
export const zTrustedList = z.object({
  /** `TSLType` URI. */
  tslType: z.string().optional(),
  /** `SchemeOperatorName` (English name when available). */
  schemeOperatorName: z.string().optional(),
  /** `SchemeTerritory`, the country code of the list (e.g. `ES`), or `EU` for the LOTL. */
  schemeTerritory: z.string().optional(),
  /** `TSLSequenceNumber`. */
  sequenceNumber: z.number().optional(),
  /** `ListIssueDateTime` (ISO 8601). */
  listIssueDateTime: z.string().optional(),
  /** `NextUpdate` (ISO 8601), when present. */
  nextUpdate: z.string().optional(),
  providers: z.array(zTrustServiceProvider),
  /** `PointersToOtherTSL` entries (e.g. the EU LOTL). Not followed by v1. */
  pointersToOtherLists: z.array(zTrustedListPointer).optional(),
})
export type TrustedList = z.infer<typeof zTrustedList>

/**
 * A flattened trust anchor: one digital identity with the service context it was
 * published under. The normalized unit both certificate-chain validation and AKI
 * emission consume — the ETSI TS 119 612 counterpart of a `@owf/eudi-lote`
 * TrustedEntity service certificate.
 */
export const zTrustAnchor = z.object({
  /** base64 DER certificate, when the identity embeds one. */
  certificate: z.string().optional(),
  subjectName: z.string().optional(),
  subjectKeyIdentifier: z.string().optional(),
  serviceTypeIdentifier: z.string(),
  serviceStatus: z.string(),
  providerName: z.string().optional(),
})
export type TrustAnchor = z.infer<typeof zTrustAnchor>
