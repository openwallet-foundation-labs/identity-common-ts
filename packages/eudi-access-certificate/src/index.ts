/**
 * EUDI Wallet-Relying Party Access Certificates
 *
 * The ETSI TS 119 411-8 V1.1.1 profile (Access Certificate Policy for EUDI Wallet Relying
 * Parties) on top of `@owf/x509`: parse, validate and create access certificates. Use
 * `@owf/x509` directly for signature, chain link and CRL checks on `accessCertificate.certificate`.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/11941108/01.01.01_60/ts_11941108v010101p.pdf
 *
 * @packageDocumentation
 */

export { AccessCertificateException } from './access-certificate-exception'
export type { AccessCertificatePolicy, AccessCertificateSubjectType } from './constants'
export { ACCESS_CERTIFICATE_POLICIES, ACCESS_CERTIFICATE_POLICY_INFO } from './constants'
export {
  assembleAccessCertificate,
  createAccessCertificate,
  prepareAccessCertificate,
  toCertificateTemplate,
} from './create'
export { getAccessCertificateSubjectIdentifier, parseAccessCertificate, toAccessCertificate } from './profile'
export {
  LEGAL_PERSON_IDENTIFIER_TYPES,
  NATURAL_PERSON_IDENTIFIER_TYPES,
  parseSemanticIdentifier,
} from './semantic-identifier'
export type * from './types'
export type {
  AccessCertificateIssue,
  AccessCertificateValidationCode,
  AccessCertificateValidationResult,
} from './validate'
export {
  ACCESS_CERTIFICATE_VALIDATION_CODES,
  assertValidAccessCertificate,
  parseAndValidateAccessCertificate,
  validateAccessCertificate,
} from './validate'
