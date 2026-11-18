/**
 * @owf/eudi-jades
 *
 * JAdES (JSON Advanced Electronic Signatures) implementation
 * based on ETSI TS 119 182-1 standard.
 *
 * Supports the following JAdES baseline profiles:
 * - B-B (Basic - Baseline): Basic signature format
 * - B-T (Basic with Time): Signatures with timestamp
 * - B-LT (Basic Long-Term): Signatures with validation data
 * - B-LTA (Basic Long-Term with Archive timestamps)
 *
 * @packageDocumentation
 */

// Constants
export { CommitmentOids, CRITICAL_PARAMETERS, DETACHED_MECHANISM_IDS, JadesProfile } from './constants'
// Error
export { JadesError, JadesValidationError } from './jades-error'
// Profile validation
export type { ProfileValidationOptions, ProfileValidationResult } from './profile'
export { detectProfiles, validateProfile } from './profile'
// Zod Schemas
export {
  zAdoTst,
  zArcTst,
  zCertId,
  zClaimedSigningTime,
  zCommitmentReference,
  zEtsiU,
  zEtsiUClearInstance,
  zOid,
  zPkiObject,
  zProtectedHeader,
  zProtectedHeaderForSigning,
  zProtectedHeaderParams,
  zRRefs,
  zRVals,
  zSigD,
  zSignAlg,
  zSignaturePolicy,
  zSignaturePolicyQualifier,
  zSignaturePolicyStore,
  zSignatureProductionPlace,
  zSignerAttributes,
  zSigTst,
  zTstContainer,
  zTstToken,
  zTstTokens,
  zUnprotectedHeader,
  zValidationValues,
  zX5tO,
  zXRefs,
  zXVals,
} from './schemas'
// Signing
export type { JadesSerialization, JadesSerializations, SignJadesOptions, SignJadesResult } from './sign'
export { signJades } from './sign'
// Types
export type {
  AdoTst,
  ArcTst,
  CertId,
  CommitmentReference,
  EtsiU,
  EtsiUClearInstance,
  Oid,
  PkiObject,
  ProtectedHeader,
  ProtectedHeaderParams,
  RRefs,
  RVals,
  SigD,
  SignAlg,
  SignaturePolicy,
  SignatureProductionPlace,
  SignerAttributes,
  SigTst,
  TstContainer,
  TstToken,
  TstTokens,
  UnprotectedHeaderParams,
  ValidationValues,
  X5tO,
  XRefs,
  XVals,
} from './types'
// Utility functions
export { generateSigX5ts, generateX5c, generateX5tO, generateX5tS256, getSigningTime } from './utils'
// Validation
export type { JadesValidationCode, JadesValidationIssue, JadesValidationResult } from './validation'
export { JADES_VALIDATION_CODES } from './validation'
// Decoding and verification
export type {
  DecodedJades,
  DecodeJadesOptions,
  VerifyJadesJwtOptions,
  VerifyJadesOptions,
  VerifyJadesResult,
} from './verify'
export { decodeJades, verifyJades, verifyJadesJwt } from './verify'
