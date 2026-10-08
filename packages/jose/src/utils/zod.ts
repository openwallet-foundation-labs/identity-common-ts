import { type BaseSchema, parseWithZod } from '@owf/identity-common'
import type z from 'zod'
import { JoseValidationError } from '../error'

/**
 * Validates `data` against `schema`, throwing a {@link JoseValidationError} that describes every
 * issue when it does not match.
 *
 * Unlike a bare `schema.parse`, the data is not included in the error message: a JOSE structure
 * regularly carries values that should not end up in a log.
 */
export function parseWithErrorHandling<Schema extends BaseSchema>(
  schema: Schema,
  data: unknown,
  errorMessage: string
): z.infer<Schema> {
  const result = parseWithZod(schema, data, errorMessage)

  if (!result.success) {
    throw new JoseValidationError(result.failure.message, { details: result.failure.issues })
  }

  return result.data
}

/**
 * `T` with the keys in `K` made optional, leaving every other key as it was.
 *
 * Written as two mapped types over `keyof T` rather than as `Omit<T, K> & Partial<Pick<T, K>>`,
 * because `Omit` reduces a type carrying an index signature — which every `.loose()` schema does — to
 * that index signature alone, dropping the declared members and their types along with it.
 */
export type MarkOptional<T, K extends PropertyKey> = {
  [P in keyof T as P extends K ? never : P]: T[P]
} & {
  [P in keyof T as P extends K ? P : never]?: T[P]
}

// Helper type to check if a schema is provided
type IsSchemaProvided<T> = T extends undefined ? false : true

/**
 * The output of `ProvidedSchema` when one was given, and the output of `DefaultSchema` otherwise.
 *
 * This is what lets a caller pass its own header or payload schema to a decode or verify function
 * and get the narrowed type back, while a caller that passes nothing gets the registered
 * JOSE structure.
 */
export type InferSchemaOrDefaultOutput<
  ProvidedSchema extends BaseSchema | undefined,
  DefaultSchema extends BaseSchema,
> =
  IsSchemaProvided<ProvidedSchema> extends true
    ? ProvidedSchema extends BaseSchema
      ? z.infer<ProvidedSchema>
      : never
    : z.infer<DefaultSchema>
