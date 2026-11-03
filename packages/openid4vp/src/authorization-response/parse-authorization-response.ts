import { type CallbackContext, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'
import { getOpenid4vpClientId } from '../client-identifier-prefix/parse-client-identifier-prefix'
import type { VerifiedJarmAuthorizationResponse } from '../jarm/jarm-authorization-response/verify-jarm-authorization-response'
import type { JarmHeader } from '../jarm/jarm-authorization-response/z-jarm-authorization-response'
import { isJarmResponseMode } from '../jarm/jarm-response-mode'
import { parseOpenid4vpAuthorizationResponsePayload } from './parse-authorization-response-payload'
import { parseJarmAuthorizationResponse } from './parse-jarm-authorization-response'
import { validateOpenid4vpAuthorizationResponsePayload } from './validate-authorization-response'
import type { ValidateOpenid4vpAuthorizationResponseResult } from './validate-authorization-response-result'
import type { Openid4vpAuthorizationResponse } from './z-authorization-response'

export interface ParseOpenid4vpAuthorizationResponseOptions {
  /**
   * The authorization response as received from the wallet, and can optionally still be encrypted.
   */
  authorizationResponse: Record<string, unknown>

  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  callbacks: Pick<CallbackContext, 'decryptJwe' | 'verifyJws'>

  origin?: string

  /**
   * Date to verify the `exp`, `nbf` and `iat` of a JARM response against. If not provided the current date
   * will be used.
   */
  now?: Date

  /**
   * Allowed clock skew in seconds for the `exp`, `nbf` and `iat` checks of a JARM response.
   *
   * @default 30
   */
  allowedSkewInSeconds?: number
}

export type ParsedOpenid4vpAuthorizationResponse = ValidateOpenid4vpAuthorizationResponseResult & {
  authorizationResponsePayload: Openid4vpAuthorizationResponse
  expectedNonce: string
  jarm?: VerifiedJarmAuthorizationResponse & {
    jarmHeader: JarmHeader
  }
}

export async function parseOpenid4vpAuthorizationResponse(
  options: ParseOpenid4vpAuthorizationResponseOptions
): Promise<ParsedOpenid4vpAuthorizationResponse> {
  const { authorizationResponse, callbacks, authorizationRequestPayload, origin } = options

  const expectedClientId = getOpenid4vpClientId({
    origin,
    responseMode: authorizationRequestPayload.response_mode,
    clientId: authorizationRequestPayload.client_id,
    legacyClientIdScheme: authorizationRequestPayload.client_id_scheme,
  })
  if (authorizationResponse.response) {
    return parseJarmAuthorizationResponse({
      now: options.now,
      allowedSkewInSeconds: options.allowedSkewInSeconds,
      jarmResponseJwt: authorizationResponse.response as string,
      callbacks,
      authorizationRequestPayload,
      expectedClientId: expectedClientId.effectiveClientId,
    })
  }

  const authorizationResponsePayload = parseOpenid4vpAuthorizationResponsePayload(authorizationResponse)

  const validatedOpenid4vpResponse = validateOpenid4vpAuthorizationResponsePayload({
    authorizationRequestPayload: authorizationRequestPayload,
    authorizationResponsePayload: authorizationResponsePayload,
  })

  if (authorizationRequestPayload.response_mode && isJarmResponseMode(authorizationRequestPayload.response_mode)) {
    throw new Oauth2ServerErrorResponseError(
      {
        error: 'invalid_request',
        error_description: 'Invalid response mode for openid4vp response. Expected jarm response.',
      },
      {
        status: 400,
      }
    )
  }

  return {
    ...validatedOpenid4vpResponse,
    expectedNonce: authorizationRequestPayload.nonce,

    authorizationResponsePayload,
    jarm: undefined,
  }
}
