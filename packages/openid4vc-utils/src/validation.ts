import { addValidationIssue } from '@owf/identity-common'
import z from 'zod'
import { getGlobalConfig } from './config'

export const zHttpsUrl = z.url().superRefine((url, ctx) => {
  const { allowInsecureUrls } = getGlobalConfig()
  // the scheme is case-insensitive (RFC 3986 §3.1)
  if (allowInsecureUrls ? /^https?:\/\//i.test(url) : /^https:\/\//i.test(url)) return
  addValidationIssue(ctx, {
    code: 'invalid_format',
    message: 'url must be an https:// url',
    context: { format: 'https_url' },
  })
})

export const zDataUrl = z.string().regex(/data:[\w/\-.]+(\+[\w/\-.]+)?;\w+,.*/, 'url must be a data URL')

export const zInteger = z.number().int()

export const zHttpMethod = z.enum(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT', 'PATCH'])
export type HttpMethod = z.infer<typeof zHttpMethod>

export const zStringToJson = z.string().transform((string, ctx) => {
  try {
    return JSON.parse(string)
  } catch (_error) {
    addValidationIssue(ctx, {
      code: 'invalid_format',
      message: 'Expected a JSON string, but could not parse the string to JSON',
      context: { format: 'json' },
    })
    return z.NEVER
  }
})

export const zIs = <Schema extends z.ZodSchema>(schema: Schema, data: unknown): data is z.infer<typeof schema> =>
  schema.safeParse(data).success
