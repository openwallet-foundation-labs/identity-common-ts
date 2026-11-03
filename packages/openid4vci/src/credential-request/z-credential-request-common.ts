import type { InferOutputUnion, Simplify } from '@openid4vc/utils'
import { addValidationIssue, zNonEmptyString } from '@owf/identity-common'
import { zJwk } from '@owf/jose'
import z from 'zod'
import {
  zAttestationProofTypeIdentifier,
  zCredentialRequestProofAttestation,
  zCredentialRequestProofDiVp,
  zCredentialRequestProofJwt,
  zDiVpProofTypeIdentifier,
  zJwtProofTypeIdentifier,
} from '../formats/proof-type'

const zCredentialRequestProofCommon = z
  .object({
    proof_type: zNonEmptyString,
  })
  .loose()

export const allCredentialRequestProofs = [
  zCredentialRequestProofJwt,
  zCredentialRequestProofAttestation,
  zCredentialRequestProofDiVp,
] as const

export const zCredentialRequestProof = z.union([
  zCredentialRequestProofCommon,
  z.discriminatedUnion('proof_type', allCredentialRequestProofs),
])

// OpenID4VCI 1.0 Section 8.2: the value of the proof type is a non-empty array
const zCredentialRequestProofsCommon = z.record(z.string(), z.array(z.unknown()).min(1))
export const zCredentialRequestProofs = z.object({
  [zJwtProofTypeIdentifier.value]: z.optional(z.array(zCredentialRequestProofJwt.shape.jwt)),
  [zAttestationProofTypeIdentifier.value]: z.optional(z.array(zCredentialRequestProofAttestation.shape.attestation)),
  [zDiVpProofTypeIdentifier.value]: z.optional(z.array(zCredentialRequestProofDiVp.shape.di_vp)),
})

type CredentialRequestProofCommon = z.infer<typeof zCredentialRequestProofCommon>
export type CredentialRequestProofFormatSpecific = InferOutputUnion<typeof allCredentialRequestProofs>
export type CredentialRequestProofWithFormats = Simplify<
  CredentialRequestProofCommon & CredentialRequestProofFormatSpecific
>
export type CredentialRequestProof = z.infer<typeof zCredentialRequestProof>

export type CredentialRequestProofsCommon = z.infer<typeof zCredentialRequestProofsCommon>
export type CredentialRequestProofsFormatSpecific = z.infer<typeof zCredentialRequestProofs>
export type CredentialRequestProofsWithFormat = CredentialRequestProofsCommon & CredentialRequestProofsFormatSpecific
export type CredentialRequestProofs = z.infer<typeof zCredentialRequestProofs>

export const zCredentialResponseEncryption = z
  .object({
    jwk: zJwk,
    // `alg` is no longer required: per OpenID4VCI V1 the key management algorithm is carried in the
    // `jwk`. It is kept as an optional sibling for backwards compatibility with draft 14/15, where it
    // was a required top-level member.
    alg: z.optional(z.string()),
    enc: zNonEmptyString,
    zip: z.optional(z.string()),
  })
  .loose()

export type CredentialResponseEncryption = z.infer<typeof zCredentialResponseEncryption>

export const zCredentialRequestCommon = z
  .object({
    proof: zCredentialRequestProof.optional(),
    proofs: z.optional(
      z.intersection(zCredentialRequestProofsCommon, zCredentialRequestProofs).superRefine((proofs, ctx) => {
        const count = Object.values(proofs).length
        if (count === 1) return
        const message = `The 'proofs' object in a credential request should contain exactly one attribute`
        if (count === 0) {
          addValidationIssue(ctx, {
            code: 'too_small',
            message,
            context: { minimum: 1, inclusive: true, origin: 'object' },
          })
        } else {
          addValidationIssue(ctx, {
            code: 'too_big',
            message,
            context: { maximum: 1, inclusive: true, origin: 'object' },
          })
        }
      })
    ),

    credential_response_encryption: zCredentialResponseEncryption.optional(),
  })
  .loose()
  .superRefine(({ proof, proofs }, ctx) => {
    if (proof === undefined || proofs === undefined) return
    addValidationIssue(ctx, {
      code: 'not_allowed',
      path: ['proofs'],
      message: `Both 'proof' and 'proofs' are defined. Only one is allowed`,
    })
  })
