import { parseWithErrorHandling } from '@openid4vc/utils'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { verifyCredentialResponseEncryption } from './verify-credential-response-encryption'
import { type DeferredCredentialRequest, zDeferredCredentialRequest } from './z-credential-request'

export interface ParseDeferredCredentialRequestOptions {
  deferredCredentialRequest: Record<string, unknown>

  /**
   * The `credential_response_encryption` of the request is checked against the
   * `credential_response_encryption` of the issuer metadata.
   */
  issuerMetadata: IssuerMetadataResult
}

export interface ParseDeferredCredentialRequestReturn {
  /**
   * The validated credential request. If both `format` and `credentialIdentifier` are
   * undefined you can still handle the request by using this object directly.
   */
  deferredCredentialRequest: DeferredCredentialRequest
}

export function parseDeferredCredentialRequest(
  options: ParseDeferredCredentialRequestOptions
): ParseDeferredCredentialRequestReturn {
  const deferredCredentialRequest = parseWithErrorHandling(
    zDeferredCredentialRequest,
    options.deferredCredentialRequest,
    'Error validating credential request'
  )

  verifyCredentialResponseEncryption(
    deferredCredentialRequest.credential_response_encryption,
    options.issuerMetadata.credentialIssuer
  )

  return {
    deferredCredentialRequest,
  }
}
