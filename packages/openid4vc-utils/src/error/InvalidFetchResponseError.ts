import type { FetchResponse } from '../globals'
import { Openid4vcBaseError } from './Openid4vcBaseError'

/**
 * The response to a request was not the one expected. The body of the response is `textResponse`, and is not part of
 * the message: the URL can be chosen by whoever sent the request, and the message may be returned to them, which
 * would let them read the responses of internal endpoints.
 */
export class InvalidFetchResponseError extends Openid4vcBaseError {
  public readonly response: FetchResponse

  public constructor(
    message: string,
    public readonly textResponse: string,
    response: FetchResponse
  ) {
    super(message)

    this.response = response.clone()
  }
}
