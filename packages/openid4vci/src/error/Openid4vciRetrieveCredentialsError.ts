import { validationErrorMessage } from '@owf/identity-common'
import type { RetrieveCredentialsResponseNotOk } from '../credential-request/retrieve-credentials'
import { Openid4vciError } from './Openid4vciError'

export class Openid4vciRetrieveCredentialsError extends Openid4vciError {
  public constructor(
    message: string,
    public response: RetrieveCredentialsResponseNotOk,
    responseText: string
  ) {
    const errorData =
      (response.credentialResponseResult?.success ? response.credentialResponseResult.data : undefined) ??
      (response.credentialErrorResponseResult?.success ? response.credentialErrorResponseResult.data : undefined) ??
      (response.credentialResponseResult?.success === false
        ? validationErrorMessage('Invalid credential response', response.credentialResponseResult.issues)
        : undefined) ??
      responseText

    super(`${message}\n${JSON.stringify(errorData, null, 2)}`)
  }
}
