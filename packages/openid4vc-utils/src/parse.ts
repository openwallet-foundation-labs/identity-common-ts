import { parseWithErrorHandling as parseWithZodErrorHandling } from '@owf/identity-common'
import type z from 'zod'
import { JsonParseError } from './error/JsonParseError'

export type BaseSchema = z.ZodTypeAny
// biome-ignore lint/suspicious/noExplicitAny: no explanation
export type InferOutputUnion<T extends readonly any[]> = {
  [K in keyof T]: z.infer<T[K]>
}[number]

export function stringToJsonWithErrorHandling(string: string, errorMessage?: string) {
  try {
    return JSON.parse(string)
  } catch (_error) {
    throw new JsonParseError(errorMessage ?? 'Unable to parse string to JSON.', string)
  }
}

export function parseIfJson<T>(data: T): T | Record<string, unknown> {
  if (typeof data !== 'string') {
    return data
  }

  try {
    // Try to parse the string as JSON
    return JSON.parse(data)
  } catch (_error) {}

  return data
}

export function parseWithErrorHandling<Schema extends BaseSchema>(
  schema: Schema,
  data: unknown,
  customErrorMessage?: string
): z.infer<Schema> {
  // NOTE: the data used to be included in the fallback message. It is not any more: these
  // structures regularly carry values that should not end up in a log.
  return parseWithZodErrorHandling(schema, data, customErrorMessage ?? 'Error validating schema')
}
