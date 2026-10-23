import { type CallbackContext, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { ContentType } from '@openid4vc/utils'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { verifyCredentialRequestEncryption } from './verify-credential-request-encryption'

export interface DecodeCredentialRequestOptions {
  /** Raw JWE string for application/jwt, or a parsed object for application/json. */
  body: unknown
  contentType: string | undefined
  issuerMetadata: IssuerMetadataResult
  callbacks: Pick<CallbackContext, 'decryptJwe'>
}

export interface DecodeCredentialRequestReturn {
  credentialRequest: Record<string, unknown>
}

const invalidCredentialRequest = (error_description: string) =>
  new Oauth2ServerErrorResponseError({
    error: Oauth2ErrorCodes.InvalidCredentialRequest,
    error_description,
  })

const invalidEncryptionParameters = (error_description: string) =>
  new Oauth2ServerErrorResponseError({
    error: Oauth2ErrorCodes.InvalidEncryptionParameters,
    error_description,
  })

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Decodes the transport envelope before the existing request parsers validate its contents.
 * Callback exceptions propagate to the caller as server failures, not protocol errors.
 */
async function decodeRequest(options: DecodeCredentialRequestOptions): Promise<DecodeCredentialRequestReturn> {
  const contentType = options.contentType?.split(';', 1)[0].trim().toLowerCase()

  if (contentType === ContentType.Jwt) {
    if (typeof options.body !== 'string') {
      throw invalidEncryptionParameters('Encrypted Credential Request body must be a compact JWE string')
    }

    const { jwk, header } = verifyCredentialRequestEncryption({
      jwe: options.body,
      credentialIssuerMetadata: options.issuerMetadata.credentialIssuer,
    })
    if (header.zip !== undefined) {
      throw invalidEncryptionParameters('Compressed Credential Requests are not supported')
    }

    const result = await options.callbacks.decryptJwe(options.body, { jwk })
    if (!result.decrypted) {
      throw invalidEncryptionParameters('Unable to decrypt Credential Request')
    }

    let payload: unknown
    try {
      payload = JSON.parse(result.payload)
    } catch {
      throw invalidCredentialRequest('Decrypted Credential Request is not valid JSON')
    }
    if (!isRecord(payload)) {
      throw invalidCredentialRequest('Decrypted Credential Request must be a JSON object')
    }
    return { credentialRequest: payload }
  }

  if (contentType === ContentType.Json) {
    if (!isRecord(options.body)) {
      throw invalidCredentialRequest('Plaintext Credential Request body must be a JSON object')
    }
    if (options.issuerMetadata.credentialIssuer.credential_request_encryption?.encryption_required) {
      throw invalidEncryptionParameters('The credential issuer requires encrypted Credential Requests')
    }
    if (Reflect.getOwnPropertyDescriptor(options.body, 'credential_response_encryption') !== undefined) {
      throw invalidEncryptionParameters(
        'Credential Requests containing credential_response_encryption must be encrypted'
      )
    }
    return { credentialRequest: options.body }
  }

  throw invalidCredentialRequest('Credential Request Content-Type must be application/json or application/jwt')
}

export function decodeCredentialRequest(
  options: DecodeCredentialRequestOptions
): Promise<DecodeCredentialRequestReturn> {
  return decodeRequest(options)
}

export function decodeDeferredCredentialRequest(
  options: DecodeCredentialRequestOptions
): Promise<DecodeCredentialRequestReturn> {
  return decodeRequest(options)
}
