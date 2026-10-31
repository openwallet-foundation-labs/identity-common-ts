/**
 * @owf/eudi-inspector
 *
 * Parse EUDI documents and check each element against its specification: trusted lists,
 * Lists of Trusted Entities, registration and access certificates, Token Status Lists,
 * SD-JWTs and mdocs, and OpenID4VP requests for over-asking. Each finding has a path into
 * the parsed document. Signatures are verified with a Web Crypto implementation the caller
 * passes.
 *
 * @packageDocumentation
 */

export { type AccessCertificateOptions, inspectAccessCertificate } from './access-certificate'
export { type DocumentFormat, detect } from './detect'
export type { DocumentInput } from './input'
export { INSPECTORS, type InspectOptions, inspect } from './inspect'
export {
  type DocumentKind,
  type Inspection,
  InspectionError,
  type SignatureCheck,
  type SignatureResult,
} from './inspection'
export { inspectLoTE, type LoTEOptions } from './lote'
export { inspectMdoc, MDOC_CODES } from './mdoc'
export { checkRequest, parseRequest } from './over-asking'
export { anchorOf, formatPath, type Path, pathKey } from './paths'
export { inspectRegistrationCertificate, type RegistrationCertificateOptions } from './registration-certificate'
export { type InspectionReport, report, toJson } from './report'
export { inspectSdJwt, SD_JWT_CODES, type SdJwtOptions } from './sd-jwt'
export { compress, decompress, fromFragment, MAX_LINK_LENGTH, type SharedValue, toFragment } from './share'
export { type GivenKeys, parseKeys, type VerificationKey, verifyJwsSignature } from './signature'
export { inspectStatusList, type StatusListOptions } from './status-list'
export { EU_LOTL_URL, inspectTrustedList, isLotl, type TrustedListOptions } from './trusted-list'
