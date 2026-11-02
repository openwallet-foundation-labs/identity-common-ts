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
export { CommitmentOIDs, CRITICAL_PARAMETERS, DETACHED_MECHANISM_IDS, JAdESProfile } from './constants'
// Error
export { JAdESError } from './jades-error'
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
  zCompactJWS,
  zEtsiU,
  zEtsiUClearInstance,
  zFlattenedJWS,
  zGeneralJWS,
  zOId,
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
  zSignOptions,
  zSigTst,
  zTstContainer,
  zTstToken,
  zTstTokens,
  zUnprotectedHeader,
  zValidationValues,
  zVerifyOptions,
  zX5tO,
  zXRefs,
  zXVals,
} from './schemas'
// Main Token class
export { Token } from './token'
// Types
export type {
  AdoTst,
  ArcTst,
  CertId,
  CommitmentReference,
  CompactJWS,
  EtsiU,
  EtsiUClearInstance,
  FlattenedJWS,
  GeneralJWS,
  OId,
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
  SignOptions,
  SigTst,
  TokenContext,
  TstContainer,
  TstToken,
  TstTokens,
  UnprotectedHeaderParams,
  ValidationValues,
  VerifyOptions,
  X5tO,
  XRefs,
  XVals,
} from './types'
// Utility functions
export {
  generateSigX5ts,
  generateX5c,
  generateX5tO,
  generateX5tS256,
  getLegacySigningTime,
  getSigningTime,
} from './utils'
export type { VerifyResult } from './verifier'
// Verifier functions
export { decode, verify, verifyCompact, verifyFlattened, verifyGeneral } from './verifier'
