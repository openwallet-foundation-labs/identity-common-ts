/**
 * Certificate policy identifiers defined in ETSI TS 119 411-8 clause 5.3.
 *
 * `{ itu-t(0) identified-organization(4) etsi(0) eudiwrp(194118) policy-identifiers(1) }`
 */
export const ACCESS_CERTIFICATE_POLICIES = {
  /** Normalized certificate policy for access certificates issued to natural persons */
  'NCP-n-eudiwrp': '0.4.0.194118.1.1',
  /** Normalized certificate policy for access certificates issued to legal persons */
  'NCP-l-eudiwrp': '0.4.0.194118.1.2',
  /** Qualified certificate policy for access certificates issued to natural persons */
  'QCP-n-eudiwrp': '0.4.0.194118.1.3',
  /** Qualified certificate policy for access certificates issued to legal persons */
  'QCP-l-eudiwrp': '0.4.0.194118.1.4',
} as const

export type AccessCertificatePolicy = keyof typeof ACCESS_CERTIFICATE_POLICIES

/** Whether an access certificate is issued to a natural or a legal person */
export type AccessCertificateSubjectType = 'natural' | 'legal'

export const ACCESS_CERTIFICATE_POLICY_INFO: Record<
  AccessCertificatePolicy,
  { subjectType: AccessCertificateSubjectType; qualified: boolean }
> = {
  'NCP-n-eudiwrp': { subjectType: 'natural', qualified: false },
  'NCP-l-eudiwrp': { subjectType: 'legal', qualified: false },
  'QCP-n-eudiwrp': { subjectType: 'natural', qualified: true },
  'QCP-l-eudiwrp': { subjectType: 'legal', qualified: true },
}
