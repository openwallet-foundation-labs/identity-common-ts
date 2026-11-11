import type { JwsSigner } from '@owf/jose'
import { Openid4vciError } from '../../error/Openid4vciError'
import type { CredentialConfigurationSupported } from '../../metadata/credential-issuer/z-credential-issuer-metadata'

export type CredentialRequestProofConfiguration = Pick<
  CredentialConfigurationSupported,
  'proof_types_supported' | 'cryptographic_binding_methods_supported'
>

export function getSupportedProofType(
  credentialConfiguration: CredentialRequestProofConfiguration | undefined,
  proofType: 'jwt' | 'attestation'
) {
  const proofTypesSupported = credentialConfiguration?.proof_types_supported
  if (!proofTypesSupported) return undefined

  const supportedProofType = proofTypesSupported[proofType]
  if (!supportedProofType) {
    throw new Openid4vciError(`Proof type '${proofType}' is not supported for the credential configuration`)
  }

  return supportedProofType
}

export function verifyProofSigningAlgSupported(
  supportedProofType: ReturnType<typeof getSupportedProofType>,
  proofType: 'jwt' | 'attestation',
  alg: string
) {
  if (supportedProofType && !supportedProofType.proof_signing_alg_values_supported.includes(alg)) {
    throw new Openid4vciError(
      `Proof signing alg value '${alg}' is not supported for proof type '${proofType}' in the credential configuration`
    )
  }
}

export function verifyBindingMethodSupported(
  credentialConfiguration: CredentialRequestProofConfiguration | undefined,
  signer: Pick<JwsSigner, 'method'> & { didUrl?: string }
) {
  const bindingMethods = credentialConfiguration?.cryptographic_binding_methods_supported
  if (!bindingMethods) return

  const bindingMethod = signer.method === 'did' && signer.didUrl ? `did:${signer.didUrl.split(':')[1]}` : signer.method
  const isSupported =
    bindingMethod === 'jwk'
      ? bindingMethods.includes('jwk') || bindingMethods.includes('cose_key')
      : bindingMethod.startsWith('did:') && (bindingMethods.includes('did') || bindingMethods.includes(bindingMethod))

  if (!isSupported) {
    throw new Openid4vciError(
      `Proof key binding method '${bindingMethod}' is not supported for the credential configuration. Supported binding methods are ${bindingMethods.join(', ')}`
    )
  }
}
