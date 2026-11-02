import { ValidationError, zodErrorMap } from '@owf/identity-common'
import z from 'zod'
import type { $ZodType } from 'zod/v4/core'

export const zUint8Array = z.instanceof<typeof Uint8Array<ArrayBufferLike>>(Uint8Array)

// biome-ignore lint/suspicious/noExplicitAny: no explanation
type ZodTypeAny = $ZodType<any, any, any>

export function parseStructureWithErrorHandling<Schema extends ZodTypeAny>(
  structureName: string,
  schema: Schema,
  data: unknown,
  customErrorMessage?: string
): z.infer<Schema> {
  const parseResult = z.safeParse(schema, data, { error: zodErrorMap })

  if (!parseResult.success) {
    throw new ValidationError(customErrorMessage ?? `Error decoding ${structureName}`, parseResult.error)
  }

  return parseResult.data
}

export function decodeStructureWithErrorHandling<Schema extends ZodTypeAny>(
  structureName: string,
  schema: Schema,
  data: z.input<Schema>,
  customErrorMessage?: string
): z.infer<Schema> {
  const decodeResult = z.safeDecode(schema, data, { error: zodErrorMap })

  if (!decodeResult.success) {
    throw new ValidationError(customErrorMessage ?? `Error decoding ${structureName}`, decodeResult.error)
  }

  return decodeResult.data
}

export function encodeStructureWithErrorHandling<Schema extends ZodTypeAny>(
  structureName: string,
  schema: Schema,
  data: z.output<Schema>,
  customErrorMessage?: string
): z.input<Schema> {
  const encodeResult = z.safeEncode(schema, data, { error: zodErrorMap })

  if (!encodeResult.success) {
    throw new ValidationError(customErrorMessage ?? `Error encoding ${structureName}`, encodeResult.error)
  }

  return encodeResult.data
}
