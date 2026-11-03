import type { BaseSchema } from '@owf/identity-common'
import type z from 'zod'

type IsSchemaProvided<T> = T extends undefined ? false : true

/** The output of `ProvidedSchema` when one was given, and of `DefaultSchema` otherwise. */
export type InferSchemaOrDefaultOutput<
  ProvidedSchema extends BaseSchema | undefined,
  DefaultSchema extends BaseSchema,
> =
  IsSchemaProvided<ProvidedSchema> extends true
    ? ProvidedSchema extends BaseSchema
      ? z.infer<ProvidedSchema>
      : never
    : z.infer<DefaultSchema>
