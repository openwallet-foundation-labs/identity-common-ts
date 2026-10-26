import { type CallbackContext, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { ContentType, ValidationError } from '@openid4vc/utils'
import { isMediaType } from '@owf/identity-common'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { Openid4vciVersion } from '../version'
import { type CredentialRequestBodyOptions, decryptCredentialRequest } from './decrypt-credential-request'
import { type ParseCredentialRequestReturn, parseCredentialRequest } from './parse-credential-request'
import {
  type ParseDeferredCredentialRequestReturn,
  parseDeferredCredentialRequest,
} from './parse-deferred-credential-request'

interface ParseCredentialRequestBodyOptions extends CredentialRequestBodyOptions {
  callbacks: Partial<Pick<CallbackContext, 'decryptJwe'>>
}

function validatePlaintextCredentialRequestEncryption(options: {
  issuerMetadata: IssuerMetadataResult
  hasCredentialResponseEncryption: boolean
}) {
  if (
    options.hasCredentialResponseEncryption &&
    options.issuerMetadata.originalDraftVersion === Openid4vciVersion.V1 &&
    options.issuerMetadata.credentialIssuer.credential_response_encryption !== undefined &&
    options.issuerMetadata.credentialIssuer.credential_request_encryption === undefined
  ) {
    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.ServerError,
        error_description: 'Unable to process credential response encryption',
      },
      {
        status: 500,
        internalMessage:
          'V1 issuer advertises credential response encryption without credential request encryption support',
      }
    )
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

function parseRequestPayload<TOptions, TResult>(
  parse: (options: TOptions) => TResult,
  options: TOptions,
  internalMessage: string
): TResult {
  try {
    return parse(options)
  } catch (error) {
    if (error instanceof Oauth2ServerErrorResponseError) throw error

    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.InvalidCredentialRequest,
        error_description: error instanceof ValidationError ? error.message : 'Invalid request',
      },
      {
        internalMessage,
        cause: error,
      }
    )
  }
}

function invalidCredentialRequestContentType(): Oauth2ServerErrorResponseError {
  return new Oauth2ServerErrorResponseError({
    error: Oauth2ErrorCodes.InvalidCredentialRequest,
    error_description: 'Credential request content-type must be application/json or application/jwt',
  })
}

function credentialRequestEncryptionRequired(): Oauth2ServerErrorResponseError {
  return new Oauth2ServerErrorResponseError({
    error: Oauth2ErrorCodes.InvalidEncryptionParameters,
    error_description: 'The credential issuer requires encrypted credential requests',
  })
}

export async function parseCredentialRequestBody(
  options: ParseCredentialRequestBodyOptions
): Promise<ParseCredentialRequestReturn> {
  if (isMediaType(options.contentType, ContentType.Jwt)) {
    const credentialRequest = await decryptCredentialRequest({
      body: options.body,
      issuerMetadata: options.issuerMetadata,
      callbacks: options.callbacks,
    })
    return parseRequestPayload(
      parseCredentialRequest,
      { issuerMetadata: options.issuerMetadata, credentialRequest },
      'Error verifying credential request proof jwt'
    )
  }

  if (isMediaType(options.contentType, ContentType.Json)) {
    if (options.issuerMetadata.credentialIssuer.credential_request_encryption?.encryption_required) {
      throw credentialRequestEncryptionRequired()
    }
    const parsedCredentialRequest = parseRequestPayload(
      parseCredentialRequest,
      { issuerMetadata: options.issuerMetadata, credentialRequest: options.body },
      'Error verifying credential request proof jwt'
    )
    validatePlaintextCredentialRequestEncryption({
      issuerMetadata: options.issuerMetadata,
      hasCredentialResponseEncryption: parsedCredentialRequest.credentialResponseEncryption !== undefined,
    })
    return parsedCredentialRequest
  }

  throw invalidCredentialRequestContentType()
}

export async function parseDeferredCredentialRequestBody(
  options: ParseCredentialRequestBodyOptions
): Promise<ParseDeferredCredentialRequestReturn> {
  if (isMediaType(options.contentType, ContentType.Jwt)) {
    const credentialRequest = await decryptCredentialRequest({
      body: options.body,
      issuerMetadata: options.issuerMetadata,
      callbacks: options.callbacks,
    })
    return parseRequestPayload(
      parseDeferredCredentialRequest,
      { issuerMetadata: options.issuerMetadata, deferredCredentialRequest: credentialRequest },
      'Error parsing deferred credential request'
    )
  }

  if (isMediaType(options.contentType, ContentType.Json)) {
    if (options.issuerMetadata.credentialIssuer.credential_request_encryption?.encryption_required) {
      throw credentialRequestEncryptionRequired()
    }
    const parsedDeferredCredentialRequest = parseRequestPayload(
      parseDeferredCredentialRequest,
      { issuerMetadata: options.issuerMetadata, deferredCredentialRequest: options.body },
      'Error parsing deferred credential request'
    )
    validatePlaintextCredentialRequestEncryption({
      issuerMetadata: options.issuerMetadata,
      hasCredentialResponseEncryption:
        parsedDeferredCredentialRequest.deferredCredentialRequest.credential_response_encryption !== undefined,
    })
    return parsedDeferredCredentialRequest
  }

  throw invalidCredentialRequestContentType()
}
