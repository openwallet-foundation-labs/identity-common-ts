import { type ValidationIssue, validationErrorMessage } from '@owf/identity-common'
import type { Oauth2ErrorResponse } from '../common/z-oauth2-error'
import type { Oauth2ErrorOptions } from '../error/Oauth2Error'
import { Oauth2Error } from './Oauth2Error'

interface Oauth2ServerErrorResponseErrorOptions extends Oauth2ErrorOptions {
  internalMessage?: string

  /**
   * @default 400
   */
  status?: number
}

export class Oauth2ServerErrorResponseError extends Oauth2Error {
  public readonly status: number

  public constructor(
    public readonly errorResponse: Oauth2ErrorResponse,
    options?: Oauth2ServerErrorResponseErrorOptions
  ) {
    super(
      `${options?.internalMessage ?? errorResponse.error_description}\n${JSON.stringify(errorResponse, null, 2)}`,
      options
    )
    this.status = options?.status ?? 400
  }

  /**
   * The error response for a request that does not validate. Only the given `error_description` is sent to the
   * client, as RFC 6749 Section 5.2 doesn't allow the line breaks and quotes of the issues. The issues are in the
   * message.
   */
  public static fromValidationIssues(
    errorResponse: Oauth2ErrorResponse & { error_description: string },
    issues: readonly ValidationIssue[]
  ): Oauth2ServerErrorResponseError {
    return new Oauth2ServerErrorResponseError(errorResponse, {
      internalMessage: validationErrorMessage(errorResponse.error_description, issues),
    })
  }
}
