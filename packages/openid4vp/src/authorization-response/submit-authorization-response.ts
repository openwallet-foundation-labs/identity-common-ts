import { type CallbackContext, Oauth2Error } from '@openid4vc/oauth2'
import { createFetcher, objectToQueryParams } from '@openid4vc/utils'
import { CommonMediaTypes } from '@owf/identity-common'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import { jarmAuthorizationResponseSend } from '../jarm/jarm-authorization-response-send'
import type { Openid4vpAuthorizationErrorResponse, Openid4vpAuthorizationResponse } from './z-authorization-response'

export interface SubmitOpenid4vpAuthorizationResponseOptions {
  authorizationRequestPayload: Pick<Openid4vpAuthorizationRequest, 'response_uri'>
  authorizationResponsePayload: Openid4vpAuthorizationResponse | Openid4vpAuthorizationErrorResponse
  jarm?: { responseJwt: string }
  callbacks: Pick<CallbackContext, 'fetch'>
}

export async function submitOpenid4vpAuthorizationResponse(options: SubmitOpenid4vpAuthorizationResponseOptions) {
  const { authorizationRequestPayload, authorizationResponsePayload, jarm, callbacks } = options
  const url = authorizationRequestPayload.response_uri

  if (jarm) {
    return jarmAuthorizationResponseSend({
      authorizationRequestPayload,
      jarmAuthorizationResponseJwt: jarm.responseJwt,
      callbacks,
    })
  }

  if (!url) {
    throw new Oauth2Error(
      'Failed to submit OpenID4VP Authorization Response. No redirect_uri or response_uri provided.'
    )
  }

  const fetch = createFetcher(callbacks.fetch)
  const encodedResponse = objectToQueryParams(authorizationResponsePayload)
  const submissionResponse = await fetch(url, {
    method: 'POST',
    body: encodedResponse.toString(),
    headers: {
      'Content-Type': CommonMediaTypes.XWwwFormUrlencoded,
    },
  })

  return {
    responseMode: 'direct_post',
    response: submissionResponse,
  }
}
