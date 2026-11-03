import type { BaseSchema } from '@owf/identity-common'
import type z from 'zod'

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
