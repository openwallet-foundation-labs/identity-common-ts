import type { z } from 'zod'
import { OpenidFederationError } from '../error/OpenidFederationError'

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
    const error = OpenidFederationError.fromZodError(e as z.ZodError)
    error.message = errorMessage ?? error.message
    throw error
  }
}
