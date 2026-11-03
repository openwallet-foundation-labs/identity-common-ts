import { type CallbackContext, Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { parseWithErrorHandling } from '@owf/identity-common'
import { decodeJwtHeader, zCompactJwe, zCompactJwt } from '@owf/jose'
import z from 'zod'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'
import { verifyJarmAuthorizationResponse } from '../jarm/jarm-authorization-response/verify-jarm-authorization-response'
import { zJarmHeader } from '../jarm/jarm-authorization-response/z-jarm-authorization-response'
import { isJarmResponseMode } from '../jarm/jarm-response-mode'
import type { ParsedOpenid4vpAuthorizationResponse } from './parse-authorization-response'
import { parseOpenid4vpAuthorizationResponsePayload } from './parse-authorization-response-payload'
import { validateOpenid4vpAuthorizationResponsePayload } from './validate-authorization-response'

export interface ParseJarmAuthorizationResponseOptions {
  jarmResponseJwt: string
  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  callbacks: Pick<CallbackContext, 'decryptJwe' | 'verifyJws'>

  expectedClientId: string

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

export async function parseJarmAuthorizationResponse(
  options: ParseJarmAuthorizationResponseOptions
): Promise<ParsedOpenid4vpAuthorizationResponse> {
  const { jarmResponseJwt, callbacks, authorizationRequestPayload, expectedClientId } = options

  const jarmAuthorizationResponseJwt = parseWithErrorHandling(
    z.union([zCompactJwt, zCompactJwe]),
    jarmResponseJwt,
    'Invalid jarm authorization response jwt.'
  )

  const verifiedJarmResponse = await verifyJarmAuthorizationResponse({
    jarmAuthorizationResponseJwt,
    callbacks,
    expectedClientId,
    authorizationRequestPayload,
    now: options.now,
    allowedSkewInSeconds: options.allowedSkewInSeconds,
  })

  const { header: jarmHeader } = decodeJwtHeader({
    jwt: jarmAuthorizationResponseJwt,
    headerSchema: zJarmHeader,
  })

  const authorizationResponsePayload = parseOpenid4vpAuthorizationResponsePayload(
    verifiedJarmResponse.jarmAuthorizationResponse
  )
  const validateOpenid4vpResponse = validateOpenid4vpAuthorizationResponsePayload({
    authorizationRequestPayload: authorizationRequestPayload,
    authorizationResponsePayload: authorizationResponsePayload,
  })

  if (!authorizationRequestPayload.response_mode || !isJarmResponseMode(authorizationRequestPayload.response_mode)) {
    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `The 'response_mode' parameter is not a valid JARM response mode.`,
      },
      {
        internalMessage: `The 'response_mode' parameter is not a valid JARM response mode. Current: ${authorizationRequestPayload.response_mode ?? 'fragment'}`,
      }
    )
  }

  return {
    ...validateOpenid4vpResponse,
    jarm: { ...verifiedJarmResponse, jarmHeader },

    expectedNonce: authorizationRequestPayload.nonce,
    authorizationResponsePayload,
  }
}
