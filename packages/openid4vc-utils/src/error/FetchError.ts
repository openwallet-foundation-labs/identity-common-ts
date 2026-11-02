import { Openid4vcBaseError } from './Openid4vcBaseError'

export class FetchError extends Openid4vcBaseError {
  public readonly cause?: Error

  public constructor(message: string, { cause }: { cause?: Error } = {}) {
    super(`${message}\nCause: ${cause?.message}`)
    this.cause = cause
  }
}
