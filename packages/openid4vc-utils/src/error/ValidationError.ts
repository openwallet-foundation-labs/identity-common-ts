import type { ZodError } from 'zod'
import { formatZodError } from '../zod-error'
import { Openid4vcBaseError } from './Openid4vcBaseError'

export class ValidationError extends Openid4vcBaseError {
  public zodError: ZodError | undefined

  constructor(message: string, zodError?: ZodError) {
    super(message)

    const formattedError = zodError ? formatZodError(zodError) : ''
    this.message = `${message}\n${formattedError}`

    Object.defineProperty(this, 'zodError', {
      value: zodError,
      writable: false,
      enumerable: false,
    })
  }
}
