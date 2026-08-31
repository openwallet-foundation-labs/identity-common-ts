/**
 * EUDI WRPRC (Wallet-Relying Party Registration Certificate) Package
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
  createLegalPersonWRPRC,
  createNaturalPersonWRPRC,
  createServiceProviderWRPRC,
  credential,
  WRPRCBuilder,
  wrprc,
} from './builders'
// Dialects
export type { WRPRCDialect } from './dialect'
export { normalizeWRPRCPayload, toWRPRCDialect, WRPRC_DIALECTS } from './dialect'
// Entitlements (ETSI TS 119 475 Annex A)
export {
  getIdentifierPrefix,
  hasAttestationProviderEntitlement,
  IDENTIFIER_TYPES,
  isPSPSubEntitlement,
  isValidEntitlement,
  LEGAL_PERSON_IDENTIFIER_PREFIXES,
  NATURAL_PERSON_IDENTIFIER_PREFIXES,
  PSP_SUB_ENTITLEMENTS,
  WRP_ENTITLEMENTS,
} from './entitlements'
// Schemas
export {
  ActSchema,
  ClaimSchema,
  CredentialSchema,
  IntermediarySchema,
  LegalPersonSubjectSchema,
  MultiLangStringSchema,
  NaturalPersonSubjectSchema,
  StatusSchema,
  SupervisoryAuthoritySchema,
  WRPRC_JWS_ALGORITHMS,
  WRPRCCWTHeaderSchema,
  WRPRCJWTHeaderSchema,
  WRPRCPayloadSchema,
} from './schemas'
// Signer
export { createWRPRCPayload, decodeWRPRC, parseWRPRC, signWRPRC } from './signer'
// Types
export type {
  Act,
  Claim,
  Credential,
  Intermediary,
  LegalPersonSubject,
  LegalPersonWRPRCInput,
  MultiLangString,
  NaturalPersonSubject,
  NaturalPersonWRPRCInput,
  SignedWRPRC,
  SignOptions,
  Status,
  SupervisoryAuthority,
  WRPRCCWTHeader,
  WRPRCJWTHeader,
  WRPRCPayload,
} from './types'
// Validators
export type { ValidationError, ValidationResult, WRPRCValidationCode } from './validator'
export {
  assertValidWRPRC,
  assertValidWRPRCPayload,
  isLegalPersonWRPRC,
  isNaturalPersonWRPRC,
  parseWRPRCPayload,
  validateLegalPersonWRPRC,
  validateNaturalPersonWRPRC,
  validateWRPRC,
  validateWRPRCJWTHeader,
  validateWRPRCPayload,
  WRPRC_VALIDATION_CODES,
} from './validator'

// Exception
export { WRPRCException } from './wrprc-exception'
