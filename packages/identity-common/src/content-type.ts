/**
 * Helpers for working with `Content-Type` header values as defined in
 * {@link https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3 | RFC 9110}.
 *
 * A `Content-Type` header carries a media type optionally followed by parameters,
 * e.g. `application/json; charset=utf-8`. The type and subtype are case-insensitive,
 * which means a header value can never be compared to an expected media type using
 * an exact string match.
 */

/**
 * Extract the normalized media type (`type/subtype`) from a `Content-Type` header
 * value, dropping any parameters and lowercasing the result.
 *
 * Returns `undefined` if no media type is present.
 *
 * @example
 * ```ts
 * extractMediaType('Application/JSON; charset=utf-8') // 'application/json'
 * ```
 */
export const extractMediaType = (contentType: string | undefined | null): string | undefined => {
  const mediaType = contentType?.split(';')[0].trim().toLowerCase()
  return mediaType ? mediaType : undefined
}

/**
 * Compare a `Content-Type` header value against one or more expected media types,
 * ignoring casing and any parameters on either side.
 *
 * @example
 * ```ts
 * isMediaType('application/statuslist+jwt; charset=utf-8', 'application/statuslist+jwt') // true
 * ```
 */
export const isMediaType = (
  contentType: string | undefined | null,
  expected: string | ReadonlyArray<string>
): boolean => {
  const mediaType = extractMediaType(contentType)
  if (!mediaType) return false

  const expectedMediaTypes = typeof expected === 'string' ? [expected] : expected
  return expectedMediaTypes.some((expectedMediaType) => extractMediaType(expectedMediaType) === mediaType)
}

/**
 * Normalize a JOSE `typ` value to a media type.
 *
 * RFC 7515 §4.1.9 requires recipients to treat a `typ` value without `/` as if
 * `application/` were prepended.
 */
export const normalizeJoseTyp = (typ: string): string => {
  const mediaType = typ.includes('/') ? typ : `application/${typ}`
  return extractMediaType(mediaType) ?? mediaType
}

/**
 * Compare a JOSE `typ` value with one or more expected media types.
 *
 * Both short and full forms are accepted on either side, as required by
 * RFC 7515 §4.1.9.
 */
export const isJoseTyp = (value: unknown, expected: string | ReadonlyArray<string>): boolean => {
  if (typeof value !== 'string') return false

  const normalizedValue = normalizeJoseTyp(value)
  const expectedTypes = typeof expected === 'string' ? [expected] : expected
  return expectedTypes.some((expectedType) => normalizeJoseTyp(expectedType) === normalizedValue)
}
