import { type CallbackContext, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { ContentType } from '@openid4vc/utils'
import { isMediaType } from '@owf/identity-common'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { verifyCredentialRequestEncryption } from './verify-credential-request-encryption'

export interface CredentialRequestBodyOptions {
  /** Parsed JSON object for application/json, or raw compact JWE string for application/jwt. */
  body: unknown
  contentType: string | undefined
  issuerMetadata: IssuerMetadataResult
}

export interface DecodeCredentialRequestOptions extends CredentialRequestBodyOptions {
  callbacks: Partial<Pick<CallbackContext, 'decryptJwe'>>
}

export interface DecodeCredentialRequestReturn {
  credentialRequest: unknown
  transport: 'json' | 'jwe'
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
      error_description: 'Unable to decrypt credential request',
    },
    {
      status: 500,
      cause,
      internalMessage: 'Error decoding encrypted credential request',
    }
  )

/**
 * Decodes the transport envelope before the existing request parsers validate its contents.
 * Missing callbacks and callback exceptions are reported as server failures, not protocol errors.
 */
export async function decodeCredentialRequest(
  options: DecodeCredentialRequestOptions
): Promise<DecodeCredentialRequestReturn> {
  if (isMediaType(options.contentType, ContentType.Jwt)) {
    if (typeof options.body !== 'string') {
      throw invalidEncryptionParameters('Encrypted credential request body must be a compact JWE string')
    }

    const { jwk, header } = verifyCredentialRequestEncryption(options.body, options.issuerMetadata.credentialIssuer)
    if (header.zip !== undefined) {
      throw invalidEncryptionParameters('Compressed credential requests are not supported')
    }

    if (!options.callbacks.decryptJwe) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.ServerError,
          error_description: 'Unable to decrypt credential request',
        },
        {
          status: 500,
          internalMessage: 'No decryptJwe callback was provided for encrypted credential requests',
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
      throw invalidEncryptionParameters('Unable to decrypt credential request')
    }

    let credentialRequest: unknown
    try {
      credentialRequest = JSON.parse(result.payload)
    } catch {
      throw invalidCredentialRequest('Decrypted credential request is not valid JSON')
    }
    return { credentialRequest, transport: 'jwe' }
  }

  if (isMediaType(options.contentType, ContentType.Json)) {
    const credentialRequest: unknown = options.body
    return { credentialRequest, transport: 'json' }
  }

  throw invalidCredentialRequest('Credential request content-type must be application/json or application/jwt')
}
