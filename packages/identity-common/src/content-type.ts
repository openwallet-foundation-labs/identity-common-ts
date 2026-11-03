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
 * Whether `value` is the JOSE `typ` (or `cty`) for the media type `typ`, as RFC 7515 section 4.1.9
 * compares them: in any casing, and with the `application/` prefix optional on either side, so
 * `kb+jwt` and `application/kb+jwt` are the same. Unlike a `Content-Type`, a `typ` has no
 * parameters, so `kb+jwt; charset=utf-8` does not match.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9
 */
export const isJwtTyp = (value: unknown, typ: string): boolean => {
  const normalize = (type: string) => type.toLowerCase().replace(/^application\//, '')
  return typeof value === 'string' && normalize(value) === normalize(typ)
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
 * Create an `Accept` header value that asks for `mediaTypes` in order of preference. The order of
 * the values alone expresses no preference ({@link https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1 | RFC 9110}),
 * so every media type after the first gets a lower quality value, down to `q=0.1`, which keeps all
 * of them acceptable. Duplicates are dropped.
 *
 * @example
 * ```ts
 * createAcceptHeader(['application/jwt', 'application/json']) // 'application/jwt, application/json;q=0.9'
 * ```
 */
export const createAcceptHeader = (mediaTypes: ReadonlyArray<string>): string =>
  Array.from(new Set(mediaTypes))
    .map((mediaType, index) => (index === 0 ? mediaType : `${mediaType};q=${Math.max(0.1, 1 - index / 10).toFixed(1)}`))
    .join(', ')
