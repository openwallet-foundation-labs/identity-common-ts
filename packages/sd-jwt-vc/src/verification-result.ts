import type { KbJwtHeader, KbJwtPayload } from '@sd-jwt/core'
import type { SdJwtVcPayload } from './sd-jwt-vc-payload'
import type { ResolvedTypeMetadata } from './sd-jwt-vc-type-metadata-format'
import type { TypeMetadataVerificationResult } from './type-metadata-verification'

export type VerificationResult = {
  payload: SdJwtVcPayload
  header: Record<string, unknown> | undefined
  kb:
    | {
        payload: KbJwtPayload
        header: KbJwtHeader
      }
    | undefined

  typeMetadata?: ResolvedTypeMetadata
  typeMetadataVerification?: TypeMetadataVerificationResult
}
