import { schemaIssueToValidationIssue, ValidationError, zodErrorMap } from '@owf/identity-common'
import z from 'zod'
import type { $ZodType } from 'zod/v4/core'

export const zUint8Array = z.instanceof<typeof Uint8Array<ArrayBufferLike>>(Uint8Array)

// biome-ignore lint/suspicious/noExplicitAny: no explanation
type ZodTypeAny = $ZodType<any, any, any>

// `reportInput` puts the input on each zod issue, which tells a `missing_value` from an `invalid_type`
const issuesOf = (error: z.ZodError) => error.issues.map((issue) => schemaIssueToValidationIssue(issue))

export function parseStructureWithErrorHandling<Schema extends ZodTypeAny>(
  structureName: string,
  schema: Schema,
  data: unknown,
  customErrorMessage?: string
): z.infer<Schema> {
  const parseResult = z.safeParse(schema, data, { reportInput: true, error: zodErrorMap })

  if (!parseResult.success) {
    throw new ValidationError(customErrorMessage ?? `Error decoding ${structureName}`, issuesOf(parseResult.error))
  }

  return parseResult.data
}

export function decodeStructureWithErrorHandling<Schema extends ZodTypeAny>(
  structureName: string,
  schema: Schema,
  data: z.input<Schema>,
  customErrorMessage?: string
): z.infer<Schema> {
  const decodeResult = z.safeDecode(schema, data, { reportInput: true, error: zodErrorMap })

  if (!decodeResult.success) {
    throw new ValidationError(customErrorMessage ?? `Error decoding ${structureName}`, issuesOf(decodeResult.error))
  }

  return decodeResult.data
}

export function encodeStructureWithErrorHandling<Schema extends ZodTypeAny>(
  structureName: string,
  schema: Schema,
  data: z.output<Schema>,
  customErrorMessage?: string
): z.input<Schema> {
  const encodeResult = z.safeEncode(schema, data, { reportInput: true, error: zodErrorMap })

  if (!encodeResult.success) {
    throw new ValidationError(customErrorMessage ?? `Error encoding ${structureName}`, issuesOf(encodeResult.error))
  }

  return encodeResult.data
}
