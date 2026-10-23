import { type CallbackContext, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { ContentType } from '@openid4vc/utils'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { Openid4vciVersion } from '../version'
import { verifyCredentialRequestEncryption } from './verify-credential-request-encryption'

export interface CredentialRequestBodyOptions {
  /** Raw JWE string for application/jwt, or raw JSON text or a parsed object for application/json. */
  body: unknown
  contentType: string | undefined
  issuerMetadata: IssuerMetadataResult
}

export interface DecodeCredentialRequestOptions extends CredentialRequestBodyOptions {
  callbacks: Partial<Pick<CallbackContext, 'decryptJwe'>>
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

const decodeRequestServerError = (cause: unknown) =>
  new Oauth2ServerErrorResponseError(
    {
      error: Oauth2ErrorCodes.ServerError,
      error_description: 'Unable to decrypt Credential Request',
    },
    {
      status: 500,
      cause,
      internalMessage: 'Error decoding encrypted Credential Request',
    }
  )

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Decodes the transport envelope before the existing request parsers validate its contents.
 * Missing callbacks and callback exceptions are reported as server failures, not protocol errors.
 */
async function decodeRequest(options: DecodeCredentialRequestOptions): Promise<DecodeCredentialRequestReturn> {
  const contentType = options.contentType?.split(';', 1)[0].trim().toLowerCase()

  if (contentType === ContentType.Jwt) {
    if (typeof options.body !== 'string') {
      throw invalidEncryptionParameters('Encrypted Credential Request body must be a compact JWE string')
    }

    const { jwk, header } = verifyCredentialRequestEncryption(options.body, options.issuerMetadata.credentialIssuer)
    if (header.zip !== undefined) {
      throw invalidEncryptionParameters('Compressed Credential Requests are not supported')
    }

    if (!options.callbacks.decryptJwe) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.ServerError,
          error_description: 'Unable to decrypt Credential Request',
        },
        {
          status: 500,
          internalMessage: 'No decryptJwe callback was provided for encrypted Credential Requests',
        }
      )
    }

    let result: Awaited<ReturnType<CallbackContext['decryptJwe']>>
    try {
      result = await options.callbacks.decryptJwe(options.body, { jwk })
    } catch (error) {
      throw decodeRequestServerError(error)
    }
    if (!result.decrypted) {
      throw invalidEncryptionParameters('Unable to decrypt Credential Request')
    }

    let credentialRequest: unknown
    try {
      credentialRequest = JSON.parse(result.payload)
    } catch {
      throw invalidCredentialRequest('Decrypted Credential Request is not valid JSON')
    }
    if (!isRecord(credentialRequest)) {
      throw invalidCredentialRequest('Decrypted Credential Request must be a JSON object')
    }
    return { credentialRequest }
  }

  if (contentType === ContentType.Json) {
    let credentialRequest: unknown = options.body
    if (typeof credentialRequest === 'string') {
      try {
        credentialRequest = JSON.parse(credentialRequest)
      } catch {
        throw invalidCredentialRequest('Plaintext Credential Request is not valid JSON')
      }
    }
    if (!isRecord(credentialRequest)) {
      throw invalidCredentialRequest('Plaintext Credential Request body must be a JSON object')
    }
    if (options.issuerMetadata.credentialIssuer.credential_request_encryption?.encryption_required) {
      throw invalidEncryptionParameters('The credential issuer requires encrypted Credential Requests')
    }
    if (
      Reflect.getOwnPropertyDescriptor(credentialRequest, 'credential_response_encryption') !== undefined &&
      (options.issuerMetadata.credentialIssuer.credential_request_encryption !== undefined ||
        options.issuerMetadata.originalDraftVersion === Openid4vciVersion.V1)
    ) {
      throw invalidEncryptionParameters(
        'Credential Requests containing credential_response_encryption must be encrypted'
      )
    }
    return { credentialRequest }
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
