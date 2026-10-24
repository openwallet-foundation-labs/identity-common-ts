import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { Openid4vciVersion } from '../version'

export function validateCredentialRequestTransportEncryption(options: {
  issuerMetadata: IssuerMetadataResult
  transport: 'json' | 'jwe'
  hasCredentialResponseEncryption: boolean
}) {
  if (options.transport === 'jwe') return

  if (options.issuerMetadata.credentialIssuer.credential_request_encryption?.encryption_required) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidEncryptionParameters,
      error_description: 'The credential issuer requires encrypted credential requests',
    })
  }

  if (
    options.hasCredentialResponseEncryption &&
    (options.issuerMetadata.credentialIssuer.credential_request_encryption !== undefined ||
      options.issuerMetadata.originalDraftVersion === Openid4vciVersion.V1)
  ) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidEncryptionParameters,
      error_description: 'Credential requests containing credential_response_encryption must be encrypted',
    })
  }
}
