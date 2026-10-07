import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import type { CredentialIssuerMetadata } from '../metadata/credential-issuer/z-credential-issuer-metadata'
import type { CredentialResponseEncryption } from './z-credential-request-common'

const invalidEncryptionParameters = (error_description: string) =>
  new Oauth2ServerErrorResponseError({
    error: Oauth2ErrorCodes.InvalidEncryptionParameters,
    error_description,
  })

/**
 * Checks the `credential_response_encryption` of a (deferred) credential request against the
 * `credential_response_encryption` the credential issuer advertises in its metadata (OpenID4VCI 1.0 §8.2, §12.2.4).
 *
 * @throws Oauth2ServerErrorResponseError with `invalid_encryption_parameters` when encryption is required but
 * missing, not supported, or requested with an `alg`, `enc` or `zip` value the issuer does not support
 */
export function verifyCredentialResponseEncryption(
  credentialResponseEncryption: CredentialResponseEncryption | undefined,
  credentialIssuerMetadata: Pick<CredentialIssuerMetadata, 'credential_response_encryption'>
) {
  const supported = credentialIssuerMetadata.credential_response_encryption

  if (!credentialResponseEncryption) {
    if (supported?.encryption_required) {
      throw invalidEncryptionParameters(
        `The credential issuer requires credential response encryption, but the request does not contain 'credential_response_encryption'`
      )
    }
    return
  }

  if (!supported) {
    throw invalidEncryptionParameters('The credential issuer does not support credential response encryption')
  }

  // Since OpenID4VCI 1.0 the `alg` is part of the `jwk`, earlier drafts send it next to the `jwk`
  const alg = credentialResponseEncryption.jwk.alg ?? credentialResponseEncryption.alg
  if (!alg || !supported.alg_values_supported.includes(alg)) {
    throw invalidEncryptionParameters(
      `Credential response encryption 'alg' must be one of ${supported.alg_values_supported.map((value) => `'${value}'`).join(', ')}`
    )
  }

  if (!supported.enc_values_supported.includes(credentialResponseEncryption.enc)) {
    throw invalidEncryptionParameters(
      `Credential response encryption 'enc' must be one of ${supported.enc_values_supported.map((value) => `'${value}'`).join(', ')}`
    )
  }

  // Without `zip_values_supported` the issuer does not support compression
  const zip = credentialResponseEncryption.zip
  if (zip !== undefined && !supported.zip_values_supported?.includes(zip)) {
    throw invalidEncryptionParameters(
      supported.zip_values_supported
        ? `Credential response encryption 'zip' must be one of ${supported.zip_values_supported.map((value) => `'${value}'`).join(', ')}`
        : `The credential issuer does not support compression of the credential response ('zip')`
    )
  }
}
