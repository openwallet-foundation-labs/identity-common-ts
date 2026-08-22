/** Types derived from the ETSI TS 119 182-1 V1.2.1 runtime schemas. */
import type { z } from 'zod'
import type {
  AdoTstSchema,
  CertIdSchema,
  CommitmentReferenceSchema,
  EtsiUClearInstanceSchema,
  EtsiUSchema,
  FlattenedJWSSchema,
  GeneralJWSSchema,
  OIdSchema,
  PkiObjectSchema,
  ProtectedHeaderParamsSchema,
  ProtectedHeaderSchema,
  RRefsSchema,
  RValsSchema,
  SigDSchema,
  SignAlgSchema,
  SignaturePolicySchema,
  SignatureProductionPlaceSchema,
  SignerAttributesSchema,
  SignOptionsSchema,
  SigTstSchema,
  TstContainerSchema,
  TstTokenSchema,
  TstTokensSchema,
  UnprotectedHeaderSchema,
  ValidationValuesSchema,
  VerifyOptionsSchema,
  X5tOSchema,
  XRefsSchema,
  XValsSchema,
} from './schemas'

export type SignAlg = z.infer<typeof SignAlgSchema>
export type OId = z.infer<typeof OIdSchema>
export type PkiObject = z.infer<typeof PkiObjectSchema>
export type TstToken = z.infer<typeof TstTokenSchema>
export type TstContainer = z.infer<typeof TstContainerSchema>
export type TstTokens = z.infer<typeof TstTokensSchema>
export type X5tO = z.infer<typeof X5tOSchema>
export type CommitmentReference = z.infer<typeof CommitmentReferenceSchema>
export type SignatureProductionPlace = z.infer<typeof SignatureProductionPlaceSchema>
export type SignerAttributes = z.infer<typeof SignerAttributesSchema>
export type SignaturePolicy = z.infer<typeof SignaturePolicySchema>
export type SigD = z.infer<typeof SigDSchema>
export type ProtectedHeaderParams = z.infer<typeof ProtectedHeaderParamsSchema>
export type ProtectedHeader = z.infer<typeof ProtectedHeaderSchema>
export type UnprotectedHeaderParams = z.infer<typeof UnprotectedHeaderSchema>
export type EtsiU = z.infer<typeof EtsiUSchema>
export type EtsiUClearInstance = z.infer<typeof EtsiUClearInstanceSchema>
export type SigTst = z.infer<typeof SigTstSchema>
export type AdoTst = z.infer<typeof AdoTstSchema>
export type XVals = z.infer<typeof XValsSchema>
export type RVals = z.infer<typeof RValsSchema>
export type ValidationValues = z.infer<typeof ValidationValuesSchema>
export type CertId = z.infer<typeof CertIdSchema>
export type XRefs = z.infer<typeof XRefsSchema>
export type RRefs = z.infer<typeof RRefsSchema>
export type ArcTst = TstContainer
export type GeneralJWS = z.infer<typeof GeneralJWSSchema>
export type FlattenedJWS = z.infer<typeof FlattenedJWSSchema>
export type CompactJWS = string

export type SignOptions = z.infer<typeof SignOptionsSchema> & {
  signer: (data: string) => Promise<string>
}
export type VerifyOptions = z.infer<typeof VerifyOptionsSchema>
