/**
 * Well-known ETSI TS 119 612 URIs.
 *
 * These are the standard values used by eIDAS national trusted lists. Profiled
 * lists may use their own profile-specific URIs (validated via a caller-supplied
 * {@link ProfileRule}); this library's parser is agnostic to both.
 */

/** Standard `TSLType` values (TS 119 612 clause 5.3.3). */
export const TSLType = {
  EUgeneric: 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric',
  EUlistofthelists: 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists',
} as const

/** Standard `ServiceStatus` values (TS 119 612 clause 5.5.4). */
export const ServiceStatus = {
  Granted: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
  Withdrawn: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn',
  UnderSupervision: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision',
  SupervisionCeased: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased',
  SupervisionInCessation: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation',
  Accredited: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited',
  AccreditationCeased: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased',
  AccreditationRevoked: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked',
  SetByNationalLaw: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw',
  RecognisedAtNationalLevel: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel',
  DeprecatedAtNationalLevel: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel',
} as const

/**
 * Service statuses that denote a currently active / trustworthy service under
 * TS 119 612. Use as the `serviceStatus` filter when extracting trust anchors
 * from a standard eIDAS list; withdrawn/ceased services are excluded.
 */
export const ACTIVE_SERVICE_STATUSES: string[] = [
  ServiceStatus.Granted,
  ServiceStatus.UnderSupervision,
  ServiceStatus.Accredited,
  ServiceStatus.SetByNationalLaw,
  ServiceStatus.RecognisedAtNationalLevel,
]

/** Common standard `ServiceTypeIdentifier` values (TS 119 612 Annex D). */
export const ServiceType = {
  /** Qualified certificate CA. */
  CA_QC: 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
  /** Public key certificate CA. */
  CA_PKC: 'http://uri.etsi.org/TrstSvc/Svctype/CA/PKC',
  /** Qualified timestamping authority. */
  TSA_QTST: 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST',
  /** Qualified electronic delivery service. */
  EDS_Q: 'http://uri.etsi.org/TrstSvc/Svctype/EDS/Q',
  /** OCSP responder for qualified certificates. */
  OCSP_QC: 'http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC',
} as const
