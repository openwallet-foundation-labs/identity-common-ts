import { URL } from '@openid4vc/utils'
import { parseWithSchema, unionParams, validationErrorMessage } from '@owf/identity-common'
import z from 'zod'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import {
  type AuthorizationErrorResponse,
  type AuthorizationResponse,
  zAuthorizationErrorResponse,
  zAuthorizationResponse,
} from './z-authorization-response'

export interface ParseAuthorizationResponseOptions {
  url: string
}

/**
 * Parse an authorization response redirect URL.
 *
 * @throws {Oauth2ServerErrorResponseError}
 */
export function parseAuthorizationResponseRedirectUrl(
  options: ParseAuthorizationResponseOptions
): AuthorizationResponse | AuthorizationErrorResponse {
  const searchParams = Object.fromEntries(new URL(options.url).searchParams)

  const parsedAuthorizationResponse = parseWithSchema(
    z.union(
      [zAuthorizationErrorResponse, zAuthorizationResponse],
      unionParams('Invalid authorization response', ['error response', 'authorization code response'])
    ),
    searchParams
  )

  if (!parsedAuthorizationResponse.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: validationErrorMessage(
        'Error occurred during validation of authorization response redirect URL.',
        parsedAuthorizationResponse.issues
      ),
    })
  }

  return parsedAuthorizationResponse.data
}
