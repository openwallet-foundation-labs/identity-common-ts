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
// Entitlements (ETSI TS 119 475 Annex A)
export {
  hasAttestationProviderEntitlement,
  IDENTIFIER_TYPES,
  isPSPSubEntitlement,
  isValidEntitlement,
  PSP_SUB_ENTITLEMENTS,
  WRP_ENTITLEMENTS,
} from './entitlements'
// Schemas
export {
  ClaimSchema,
  CredentialSchema,
  IntermediarySchema,
  LegalPersonSubjectSchema,
  MultiLangStringSchema,
  NaturalPersonSubjectSchema,
  StatusSchema,
  SupervisoryAuthoritySchema,
  WRPRCCWTHeaderSchema,
  WRPRCJWTHeaderSchema,
  WRPRCPayloadSchema,
} from './schemas'
// Signer
export { createWRPRCPayload, decodeWRPRC, parseWRPRC, signWRPRC } from './signer'
// Types
export type {
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
export {
  assertValidWRPRC,
  assertValidWRPRCPayload,
  isLegalPersonWRPRC,
  isNaturalPersonWRPRC,
  validateLegalPersonWRPRC,
  validateNaturalPersonWRPRC,
  validateWRPRC,
  validateWRPRCJWTHeader,
  validateWRPRCPayload,
} from './validator'

// Exception
export { WRPRCException } from './wrprc-exception'
