import { zNumericDate } from '@owf/identity-common'
import { zJoseType, zJwtHeader, zJwtPayload } from '@owf/jose'
import z from 'zod'
import { zCredentialIssuerMetadataDraft14Draft15V1 } from './z-credential-issuer-metadata'

export const zSignedCredentialIssuerMetadataHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: zJoseType('openidvci-issuer-metadata+jwt'),
  })
  .loose()

export type SignedCredentialIssuerMetadataHeader = z.infer<typeof zSignedCredentialIssuerMetadataHeader>

export const zSignedCredentialIssuerMetadataPayload = z
  .object({
    ...zJwtPayload.shape,
    iat: zNumericDate,
    sub: z.string(),

    // NOTE: we don't support older drafts below 14 for signed metadata
    ...zCredentialIssuerMetadataDraft14Draft15V1.shape,
  })
  .loose()

export type SignedCredentialIssuerMetadataPayload = z.infer<typeof zSignedCredentialIssuerMetadataPayload>
