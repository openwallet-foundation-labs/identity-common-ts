import type { z } from 'zod'
import { OpenIdFederationError } from '../error/OpenIdFederationError'

type ValidateOptions<Schema extends z.ZodType> = {
  data: z.input<Schema> | unknown
  schema: Schema
  errorMessage?: string
}

export const validate = <Schema extends z.ZodType>({
  schema,
  data,
  errorMessage,
}: ValidateOptions<Schema>): z.output<Schema> => {
  try {
    return schema.parse(data)
  } catch (e) {
    const error = OpenIdFederationError.fromZodError(e as z.ZodError)
    error.message = errorMessage ?? error.message
    throw error
  }
}
