import { zHttpsUrl } from '@openid4vc/utils'
import { addValidationIssue, zNumericDate, zTyp } from '@owf/identity-common'
import { zCompactJwt, zJwtHeader, zJwtPayload } from '@owf/jose'
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
    typ: zTyp('openid4vci-proof+jwt'),
  })
  .loose()
  .superRefine(refineJwtProofKeyHeaders)

/**
 * The key headers of a proof or key attestation JWT: `jwk` and `kid` are mutually exclusive,
 * and `trust_chain` requires `kid`
 */
export function refineJwtProofKeyHeaders(
  { kid, jwk, trust_chain }: { kid?: string; jwk?: unknown; trust_chain?: unknown },
  ctx: z.RefinementCtx
) {
  if (jwk !== undefined && kid !== undefined) {
    addValidationIssue(ctx, {
      code: 'not_allowed',
      path: ['jwk'],
      message: `Both 'jwk' and 'kid' are defined. Only one is allowed`,
    })
  }
  if (trust_chain && kid === undefined) {
    addValidationIssue(ctx, {
      code: 'missing_value',
      path: ['kid'],
      message: `When 'trust_chain' is provided, 'kid' is required`,
      context: { expected: 'string' },
    })
  }
}

export type CredentialRequestJwtProofTypeHeader = z.infer<typeof zCredentialRequestJwtProofTypeHeader>

export const zCredentialRequestJwtProofTypePayload = z
  .object({
    ...zJwtPayload.shape,
    aud: z.union([zHttpsUrl, z.array(zHttpsUrl)]),
    iat: zNumericDate,
  })
  .loose()

export type CredentialRequestJwtProofTypePayload = z.infer<typeof zCredentialRequestJwtProofTypePayload>
