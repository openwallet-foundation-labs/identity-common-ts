import z from 'zod'
import { getGlobalConfig } from './config'

export const zHttpsUrl = z.url().refine(
  (url) => {
    const { allowInsecureUrls } = getGlobalConfig()
    // the scheme is case-insensitive (RFC 3986 §3.1)
    return allowInsecureUrls ? /^https?:\/\//i.test(url) : /^https:\/\//i.test(url)
  },
  { message: 'url must be an https:// url' }
)

export const zDataUrl = z.string().regex(/data:[\w/\-.]+(\+[\w/\-.]+)?;\w+,.*/, 'url must be a data URL')

export const zInteger = z.number().int()

/**
 * Whether `value` is the JWT `typ` header value for the media type `application/<typ>`. Pass `typ` in its
 * short lowercase form.
 *
 * Matches the short form and the full `application/` form in any casing, as recipients must
 * treat a `typ` without a `/` as if `application/` were prepended, and media types are
 * case-insensitive (RFC 7515 Section 4.1.9).
 */
export function isJwtTyp(value: unknown, typ: string): boolean {
  if (typeof value !== 'string') return false

  const lowerCaseValue = value.toLowerCase()
  return lowerCaseValue === typ || lowerCaseValue === `application/${typ}`
}

/**
 * Schema for the JWT `typ` header value for the media type `application/<typ>`, using {@link isJwtTyp}.
 * The value is not changed, so the parsed header matches the signed one.
 *
 * The input type only allows the lowercase forms, so created JWTs use them. Prefer the short form.
 */
export const zTyp = <const Typ extends string>(typ: Typ) =>
  z.string().refine((value) => isJwtTyp(value, typ), {
    message: `Expected typ '${typ}' or 'application/${typ}' (case-insensitive)`,
  }) as z.ZodType<string, Typ | `application/${Typ}`>

export const zHttpMethod = z.enum(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT', 'PATCH'])
export type HttpMethod = z.infer<typeof zHttpMethod>

export const zStringToJson = z.string().transform((string, ctx) => {
  try {
    return JSON.parse(string)
  } catch (_error) {
    ctx.addIssue({
      code: 'custom',
      message: 'Expected a JSON string, but could not parse the string to JSON',
    })
    return z.NEVER
  }
})

export const zIs = <Schema extends z.ZodSchema>(schema: Schema, data: unknown): data is z.infer<typeof schema> =>
  schema.safeParse(data).success
