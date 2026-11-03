/** Types derived from the ETSI TS 119 182-1 V1.2.1 runtime schemas. */
import type { Hasher } from '@owf/identity-common'
import type { z } from 'zod'
import type {
  zAdoTst,
  zCertId,
  zCommitmentReference,
  zEtsiU,
  zEtsiUClearInstance,
  zFlattenedJws,
  zGeneralJws,
  zOid,
  zPkiObject,
  zProtectedHeader,
  zProtectedHeaderParams,
  zRRefs,
  zRVals,
  zSigD,
  zSignAlg,
  zSignaturePolicy,
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

export type SignAlg = z.infer<typeof zSignAlg>
export type Oid = z.infer<typeof zOid>
export type PkiObject = z.infer<typeof zPkiObject>
export type TstToken = z.infer<typeof zTstToken>
export type TstContainer = z.infer<typeof zTstContainer>
export type TstTokens = z.infer<typeof zTstTokens>
export type X5tO = z.infer<typeof zX5tO>
export type CommitmentReference = z.infer<typeof zCommitmentReference>
export type SignatureProductionPlace = z.infer<typeof zSignatureProductionPlace>
export type SignerAttributes = z.infer<typeof zSignerAttributes>
export type SignaturePolicy = z.infer<typeof zSignaturePolicy>
export type SigD = z.infer<typeof zSigD>
export type ProtectedHeaderParams = z.infer<typeof zProtectedHeaderParams>
export type ProtectedHeader = z.infer<typeof zProtectedHeader>
export type UnprotectedHeaderParams = z.infer<typeof zUnprotectedHeader>
export type EtsiU = z.infer<typeof zEtsiU>
export type EtsiUClearInstance = z.infer<typeof zEtsiUClearInstance>
export type SigTst = z.infer<typeof zSigTst>
export type AdoTst = z.infer<typeof zAdoTst>
export type XVals = z.infer<typeof zXVals>
export type RVals = z.infer<typeof zRVals>
export type ValidationValues = z.infer<typeof zValidationValues>
export type CertId = z.infer<typeof zCertId>
export type XRefs = z.infer<typeof zXRefs>
export type RRefs = z.infer<typeof zRRefs>
export type ArcTst = TstContainer
export type GeneralJws = z.infer<typeof zGeneralJws>
export type FlattenedJws = z.infer<typeof zFlattenedJws>
export type CompactJws = string

/** Callbacks the token needs from its host environment. */
export type TokenContext = {
  hasher: Hasher
}

export type SignOptions = z.infer<typeof zSignOptions> & {
  signer: (data: string) => Promise<string>
}
export type VerifyOptions = z.infer<typeof zVerifyOptions>
