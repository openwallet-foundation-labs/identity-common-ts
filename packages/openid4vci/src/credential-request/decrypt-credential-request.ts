import { type CallbackContext, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { verifyCredentialRequestEncryption } from './verify-credential-request-encryption'

export interface CredentialRequestBodyOptions {
  /** Parsed JSON object for application/json, or raw compact JWE string for application/jwt. */
  body: unknown
  contentType: string | undefined
  issuerMetadata: IssuerMetadataResult
}

export interface DecryptCredentialRequestOptions {
  /** Raw compact JWE string. */
  body: unknown
  issuerMetadata: IssuerMetadataResult
  callbacks: Partial<Pick<CallbackContext, 'decryptJwe'>>
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
 * Decrypts an encrypted request before the existing parser validates its contents.
 * Missing callbacks and callback exceptions are reported as server failures, not protocol errors.
 */
export async function decryptCredentialRequest(options: DecryptCredentialRequestOptions): Promise<unknown> {
  if (typeof options.body !== 'string') {
    throw invalidEncryptionParameters('Encrypted credential request body must be a compact JWE string')
  }

  const { jwk } = verifyCredentialRequestEncryption(options.body, options.issuerMetadata.credentialIssuer)

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
  return credentialRequest
}
