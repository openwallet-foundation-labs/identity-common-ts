import {
  type CreateKeyAttestationJwtOptions,
  createKeyAttestationJwt,
  type VerifyKeyAttestationJwtOptions,
  verifyKeyAttestationJwt,
} from '../../../key-attestation/key-attestation'
import {
  type CredentialRequestProofConfiguration,
  getSupportedProofType,
  verifyBindingMethodSupported,
  verifyProofSigningAlgSupported,
} from '../verify-proof-type-supported'

export interface CreateCredentialRequestAttestationProofOptions extends Omit<CreateKeyAttestationJwtOptions, 'use'> {
  /**
   * Nonce to use in the attestation. Should be derived from the c_nonce
   *
   * Required because the attestation is created for 'attestation' proof types
   */
  nonce: string

  /**
   * The date when the key attestation will expire.
   */
  expiresAt: Date
}

export async function createCredentialRequestAttestationProof(
  options: CreateCredentialRequestAttestationProofOptions
): Promise<string> {
  return createKeyAttestationJwt({
    ...options,
    use: 'proof_type.attestation',
  })
}

export interface VerifyCredentialRequestAttestationProofOptions extends Omit<VerifyKeyAttestationJwtOptions, 'use'> {
  /**
   * The credential configuration the proof is for. If provided, the proof type, the key attestation `alg`,
   * `key_attestations_required` and `cryptographic_binding_methods_supported` (the attested keys are jwks) are
   * verified against it. A check is skipped when its field is absent.
   */
  credentialConfiguration?: CredentialRequestProofConfiguration
}
export async function verifyCredentialRequestAttestationProof(options: VerifyCredentialRequestAttestationProofOptions) {
  const { credentialConfiguration, ...keyAttestationOptions } = options
  const supportedProofType = getSupportedProofType(credentialConfiguration, 'attestation')

  const verificationResult = await verifyKeyAttestationJwt({
    ...keyAttestationOptions,
    keyAttestationsRequired: options.keyAttestationsRequired ?? supportedProofType?.key_attestations_required,
    use: 'proof_type.attestation',
  })

  verifyProofSigningAlgSupported(supportedProofType, 'attestation', verificationResult.header.alg)
  verifyBindingMethodSupported(credentialConfiguration, { method: 'jwk' })

  return verificationResult
}
