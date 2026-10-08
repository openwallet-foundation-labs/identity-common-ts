import { zHttpsUrl } from '@openid4vc/utils'
import { zNumericDate } from '@owf/identity-common'
import { zCompactJwt, zJoseType, zJwtHeader, zJwtPayload } from '@owf/jose'
import z from 'zod'

export const zJwtProofTypeIdentifier = z.literal('jwt')
export const jwtProofTypeIdentifier = zJwtProofTypeIdentifier.value
export type JwtProofTypeIdentifier = z.infer<typeof zJwtProofTypeIdentifier>

export const zCredentialRequestProofJwt = z.object({
  proof_type: zJwtProofTypeIdentifier,
  jwt: zCompactJwt,
})

export const zCredentialRequestJwtProofTypeHeader = zJwtHeader
  .extend({
    key_attestation: z.optional(zCompactJwt),
    typ: zJoseType('openid4vci-proof+jwt'),
  })
  .loose()
  .refine(({ kid, jwk }) => jwk === undefined || kid === undefined, {
    message: `Both 'jwk' and 'kid' are defined. Only one is allowed`,
  })
  .refine(({ trust_chain, kid }) => !trust_chain || kid !== undefined, {
    message: `When 'trust_chain' is provided, 'kid' is required`,
  })

export type CredentialRequestJwtProofTypeHeader = z.infer<typeof zCredentialRequestJwtProofTypeHeader>

export const zCredentialRequestJwtProofTypePayload = z
  .object({
    ...zJwtPayload.shape,
    aud: z.union([zHttpsUrl, z.array(zHttpsUrl)]),
    iat: zNumericDate,
  })
  .loose()

export type CredentialRequestJwtProofTypePayload = z.infer<typeof zCredentialRequestJwtProofTypePayload>
