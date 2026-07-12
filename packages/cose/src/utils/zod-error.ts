import z from 'zod'
import { createErrorMap, fromError } from 'zod-validation-error'

z.config({
  customError: createErrorMap(),
})

function formatZodError(error?: z.ZodError): string {
  if (!error) return ''

  return fromError(error, {
    prefix: '',
    prefixSeparator: '✖ ',
    issueSeparator: '\n✖ ',
    unionSeparator: '\n    OR ✖ ',
  }).toString()
}

import type { ZodError } from 'zod'

export class ValidationError extends Error {
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
