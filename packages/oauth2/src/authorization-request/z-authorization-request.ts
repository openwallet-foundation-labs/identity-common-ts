import { zHttpsUrl } from '@openid4vc/utils'
import { zNonEmptyString } from '@owf/identity-common'
import z from 'zod'
import { zOauth2ErrorResponse } from '../common/z-oauth2-error'

export const zPushedAuthorizationRequestUriPrefix = z.literal('urn:ietf:params:oauth:request_uri:')
export const pushedAuthorizationRequestUriPrefix = zPushedAuthorizationRequestUriPrefix.value
export type PushedAuthorizationRequestUriPrefix = z.infer<typeof zPushedAuthorizationRequestUriPrefix>

// TODO: should create different request validations for different
// response types. Currently we basically only support `code`
export const zAuthorizationRequest = z
  .object({
    response_type: zNonEmptyString,
    client_id: zNonEmptyString,

    issuer_state: z.optional(zNonEmptyString),
    redirect_uri: z.url().optional(),
    resource: z.optional(zHttpsUrl),
    scope: z.optional(zNonEmptyString),
    state: z.optional(z.string()),

    // DPoP jwk thumbprint
    dpop_jkt: z.optional(z.base64url()),

    code_challenge: z.optional(zNonEmptyString),
    code_challenge_method: z.optional(zNonEmptyString),
  })
  .loose()
export type AuthorizationRequest = z.infer<typeof zAuthorizationRequest>

export const zPushedAuthorizationRequest = z
  .object({
    request_uri: zNonEmptyString,
    client_id: zNonEmptyString,
  })
  .loose()
export type PushedAuthorizationRequest = z.infer<typeof zPushedAuthorizationRequest>

export const zPushedAuthorizationResponse = z
  .object({
    request_uri: zNonEmptyString,
    expires_in: z.number().int(),
  })
  .loose()
export type PushedAuthorizationResponse = z.infer<typeof zPushedAuthorizationResponse>

export const zPushedAuthorizationErrorResponse = zOauth2ErrorResponse
export type PushedAuthorizationErrorResponse = z.infer<typeof zPushedAuthorizationErrorResponse>
