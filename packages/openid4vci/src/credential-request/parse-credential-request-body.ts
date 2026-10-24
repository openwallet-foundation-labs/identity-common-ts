import { type CallbackContext, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { ValidationError } from '@openid4vc/utils'
import type { CredentialRequestBodyOptions } from './decode-credential-request'
import { decodeCredentialRequest } from './decode-credential-request'
import { type ParseCredentialRequestReturn, parseCredentialRequest } from './parse-credential-request'
import {
  type ParseDeferredCredentialRequestReturn,
  parseDeferredCredentialRequest,
} from './parse-deferred-credential-request'
import { validateCredentialRequestTransportEncryption } from './validate-credential-request-transport-encryption'

interface ParseCredentialRequestBodyOptions extends CredentialRequestBodyOptions {
  callbacks: Partial<Pick<CallbackContext, 'decryptJwe'>>
}

export async function parseCredentialRequestBody(
  options: ParseCredentialRequestBodyOptions
): Promise<ParseCredentialRequestReturn> {
  const { credentialRequest, transport } = await decodeCredentialRequest(options)
  try {
    const parsedCredentialRequest = parseCredentialRequest({
      issuerMetadata: options.issuerMetadata,
      credentialRequest,
    })
    validateCredentialRequestTransportEncryption({
      issuerMetadata: options.issuerMetadata,
      transport,
      hasCredentialResponseEncryption: parsedCredentialRequest.credentialResponseEncryption !== undefined,
    })
    return parsedCredentialRequest
  } catch (error) {
    if (error instanceof Oauth2ServerErrorResponseError) throw error

    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.InvalidCredentialRequest,
        error_description: error instanceof ValidationError ? error.message : 'Invalid request',
      },
      {
        internalMessage: 'Error verifying credential request proof jwt',
        cause: error,
      }
    )
  }
}

export async function parseDeferredCredentialRequestBody(
  options: ParseCredentialRequestBodyOptions
): Promise<ParseDeferredCredentialRequestReturn> {
  const { credentialRequest, transport } = await decodeCredentialRequest(options)
  try {
    const parsedDeferredCredentialRequest = parseDeferredCredentialRequest({
      issuerMetadata: options.issuerMetadata,
      deferredCredentialRequest: credentialRequest,
    })
    validateCredentialRequestTransportEncryption({
      issuerMetadata: options.issuerMetadata,
      transport,
      hasCredentialResponseEncryption:
        parsedDeferredCredentialRequest.deferredCredentialRequest.credential_response_encryption !== undefined,
    })
    return parsedDeferredCredentialRequest
  } catch (error) {
    if (error instanceof Oauth2ServerErrorResponseError) throw error

    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.InvalidCredentialRequest,
        error_description: error instanceof ValidationError ? error.message : 'Invalid request',
      },
      {
        internalMessage: 'Error parsing deferred credential request',
        cause: error,
      }
    )
  }
}
