/**
 * EUDI Wallet-Relying Party Registration Certificates
 *
 * Implementation of ETSI TS 119 475 v1.2.1 - Wallet-Relying Party Registration Certificates.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 *
 * @packageDocumentation
 */

// Builders
export {
  CredentialBuilder,
  createLegalPersonRegistrationCertificate,
  createNaturalPersonRegistrationCertificate,
  createServiceProviderRegistrationCertificate,
  credential,
  RegistrationCertificateBuilder,
  registrationCertificate,
} from './builders'
// CWT
export {
  decodeRegistrationCertificateCwt,
  RegistrationCertificateCwt,
  RegistrationCertificateCwtPayload,
  signRegistrationCertificateCwt,
} from './cwt'
// Dialects
export type { RegistrationCertificateDialect } from './dialect'
export {
  normalizeRegistrationCertificatePayload,
  REGISTRATION_CERTIFICATE_DIALECTS,
  toRegistrationCertificateDialect,
} from './dialect'
// Entitlements (ETSI TS 119 475 Annex A)
export {
  getIdentifierPrefix,
  hasAttestationProviderEntitlement,
  IDENTIFIER_TYPES,
  isPspSubEntitlement,
  isValidEntitlement,
  LEGAL_PERSON_IDENTIFIER_PREFIXES,
  NATURAL_PERSON_IDENTIFIER_PREFIXES,
  PSP_SUB_ENTITLEMENTS,
  WRP_ENTITLEMENTS,
} from './entitlements'
// Over-asking
export type { OverAskingCode, OverAskingIssue, OverAskingResult, RegisteredCredential } from './over-asking'
export { checkOverAsking, OVER_ASKING_CODES } from './over-asking'
// Presentation requests
export type { Openid4vpRegistrationCertificateVerifierInfoOptions } from './presentation-request'
export {
  decodeMdocRegistrationCertificate,
  decodeOpenid4vpRegistrationCertificate,
  mdocRegistrationCertificateExtension,
  openid4vpRegistrationCertificateVerifierInfo,
} from './presentation-request'
// Error
export { RegistrationCertificateValidationError } from './registration-certificate-error'
// Schemas
export {
  REGISTRATION_CERTIFICATE_JWS_ALGORITHMS,
  zClaim,
  zCredential,
  zIntermediary,
  zLegalPersonSubject,
  zMultiLangString,
  zNaturalPersonSubject,
  zProvidedAttestation,
  zRegistrationCertificateCwtHeader,
  zRegistrationCertificateJwtHeader,
  zRegistrationCertificatePayload,
  zStatus,
  zSupervisoryAuthority,
} from './schemas'
// Signer
export {
  createRegistrationCertificatePayload,
  decodeRegistrationCertificateJwt,
  parseRegistrationCertificateJwt,
  signRegistrationCertificateJwt,
} from './signer'
// Status
export type { VerifyRegistrationCertificateStatusOptions } from './status'
export { verifyRegistrationCertificateStatus } from './status'
// Types
export type {
  Claim,
  Credential,
  Intermediary,
  LegalPersonRegistrationCertificateInput,
  LegalPersonSubject,
  MultiLangString,
  NaturalPersonRegistrationCertificateInput,
  NaturalPersonSubject,
  ProvidedAttestation,
  RegistrationCertificateCwtHeader,
  RegistrationCertificateJwtHeader,
  RegistrationCertificatePayload,
  SignCwtOptions,
  SignedRegistrationCertificateCwt,
  SignedRegistrationCertificateJwt,
  SignJwtOptions,
  Status,
  SupervisoryAuthority,
  VerifyCoseCallback,
  VerifyRegistrationCertificateCallbacks,
} from './types'
// Validators
export type {
  RegistrationCertificateValidationCode,
  RegistrationCertificateValidationContexts,
  RegistrationCertificateValidationIssue,
  ValidationResult,
} from './validator'
export {
  assertValidRegistrationCertificate,
  assertValidRegistrationCertificatePayload,
  isLegalPersonRegistrationCertificate,
  isNaturalPersonRegistrationCertificate,
  parseRegistrationCertificatePayload,
  REGISTRATION_CERTIFICATE_VALIDATION_CODES,
  validateLegalPersonRegistrationCertificate,
  validateNaturalPersonRegistrationCertificate,
  validateRegistrationCertificate,
  validateRegistrationCertificateCwtHeader,
  validateRegistrationCertificateJwtHeader,
  validateRegistrationCertificatePayload,
} from './validator'
// Verification
export type { VerifyRegistrationCertificateOptions } from './verify'
export { verifyRegistrationCertificate } from './verify'
