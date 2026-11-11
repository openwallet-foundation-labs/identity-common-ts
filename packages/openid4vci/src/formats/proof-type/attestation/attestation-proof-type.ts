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
