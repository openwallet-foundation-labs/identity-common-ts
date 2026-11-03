import { parseWithSchema, validationErrorMessage } from '@owf/identity-common'
import {
  type ParseAuthorizationRequestResult,
  parseAuthorizationRequest,
} from '../authorization-request/parse-authorization-request'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import { type AuthorizationChallengeRequest, zAuthorizationChallengeRequest } from './z-authorization-challenge'

export interface ParseAuthorizationChallengeRequestOptions {
  request: RequestLike

  authorizationChallengeRequest: unknown
}

export interface ParseAuthorizationChallengeRequestResult extends ParseAuthorizationRequestResult {
  authorizationChallengeRequest: AuthorizationChallengeRequest
}

/**
 * Parse an authorization challenge request.
 *
 * @throws {Oauth2ServerErrorResponseError}
 */
export function parseAuthorizationChallengeRequest(
  options: ParseAuthorizationChallengeRequestOptions
): ParseAuthorizationChallengeRequestResult {
  const parsedAuthorizationChallengeRequest = parseWithSchema(
    zAuthorizationChallengeRequest,
    options.authorizationChallengeRequest
  )
  if (!parsedAuthorizationChallengeRequest.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: validationErrorMessage(
        'Error occurred during validation of authorization challenge request.',
        parsedAuthorizationChallengeRequest.issues
      ),
    })
  }

  const authorizationChallengeRequest = parsedAuthorizationChallengeRequest.data
  const { clientAttestation, dpop } = parseAuthorizationRequest({
    authorizationRequest: authorizationChallengeRequest,
    request: options.request,
  })

  return {
    authorizationChallengeRequest: parsedAuthorizationChallengeRequest.data,

    dpop,
    clientAttestation,
  }
}
