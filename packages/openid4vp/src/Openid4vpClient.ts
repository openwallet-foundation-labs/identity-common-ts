import type { CallbackContext } from '@openid4vc/oauth2'
import type { ParseOpenid4vpAuthorizationRequestOptions } from './authorization-request/parse-authorization-request-params'
import { parseOpenid4vpAuthorizationRequest } from './authorization-request/parse-authorization-request-params'
import {
  type ResolveOpenid4vpAuthorizationRequestOptions,
  resolveOpenid4vpAuthorizationRequest,
} from './authorization-request/resolve-authorization-request'
import {
  type CreateOpenid4vpAuthorizationResponseOptions,
  createOpenid4vpAuthorizationResponse,
} from './authorization-response/create-authorization-response'
import {
  type SubmitOpenid4vpAuthorizationResponseOptions,
  submitOpenid4vpAuthorizationResponse,
} from './authorization-response/submit-authorization-response'
import type {
  Openid4vpAuthorizationErrorResponse,
  Openid4vpAuthorizationResponse,
} from './authorization-response/z-authorization-response'

export interface Openid4vpClientOptions {
  /**
   * Callbacks required for the openid4vp client
   */
  callbacks: Omit<CallbackContext, 'generateRandom' | 'clientAuthentication'>
}

export class Openid4vpClient {
  public constructor(private options: Openid4vpClientOptions) {}

  public parseOpenid4vpAuthorizationRequest(options: ParseOpenid4vpAuthorizationRequestOptions) {
    return parseOpenid4vpAuthorizationRequest(options)
  }

  public async resolveOpenId4vpAuthorizationRequest(
    options: Omit<ResolveOpenid4vpAuthorizationRequestOptions, 'callbacks'>
  ) {
    return resolveOpenid4vpAuthorizationRequest({ ...options, callbacks: this.options.callbacks })
  }

  public async createOpenid4vpAuthorizationResponse<
    ResponsePayload extends
      | Openid4vpAuthorizationResponse
      | Openid4vpAuthorizationErrorResponse = Openid4vpAuthorizationResponse,
  >(options: Omit<CreateOpenid4vpAuthorizationResponseOptions<ResponsePayload>, 'callbacks'>) {
    return createOpenid4vpAuthorizationResponse<ResponsePayload>({ ...options, callbacks: this.options.callbacks })
  }

  public async submitOpenid4vpAuthorizationResponse(
    options: Omit<SubmitOpenid4vpAuthorizationResponseOptions, 'callbacks'>
  ) {
    return submitOpenid4vpAuthorizationResponse({ ...options, callbacks: this.options.callbacks })
  }
}
