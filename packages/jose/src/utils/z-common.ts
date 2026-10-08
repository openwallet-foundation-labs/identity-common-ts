import { extractMediaType } from '@owf/identity-common'
import z from 'zod'

/**
 * A base64url encoded value without padding, as used everywhere in JOSE.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-2
 */
export const zBase64Url = z.string().regex(/^[A-Za-z0-9_-]*$/, {
  message: 'Expected an unpadded base64url encoded string',
})

/**
 * A StringOrURI: a string value that is compared as a case-sensitive string, and that must be a URI
 * whenever it contains a `:`.
 *
 * The URI form is not enforced, as doing so would reject tokens that are accepted in practice; the
 * type exists to name the claims RFC 7519 defines this way.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7519#section-2
 */
export const zStringOrUri = z.string()

/**
 * Normalizes a JOSE media type for comparison: parameters are dropped, casing is normalized and the
 * `application/` prefix is removed.
 *
 * RFC 7515 lets a producer omit the `application/` prefix "when it is not used in a cross-application
 * context", which means `kb+jwt` and `application/kb+jwt` are the same media type and a plain
 * `z.literal('kb+jwt')` would reject a spec-compliant token.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9
 */
export const normalizeJoseType = (type: string): string | undefined => {
  const mediaType = extractMediaType(type)
  return mediaType?.startsWith('application/') ? mediaType.slice('application/'.length) : mediaType
}

/**
 * A `typ` header parameter that must be one of `expected`, compared as JOSE media types: casing,
 * media type parameters and an `application/` prefix on either side are ignored.
 *
 * Use this instead of `z.literal` to require the type of a token, as explicit typing is what keeps
 * a token issued for one purpose from being accepted for another.
 *
 * @example
 * ```ts
 * const zKeyBindingJwtHeader = z.object({ ...zJwtHeader.shape, typ: zJoseType('kb+jwt') }).loose()
 * ```
 *
 * @see https://www.rfc-editor.org/rfc/rfc8725#section-3.11
 */
export const zJoseType = (expected: string | readonly [string, ...string[]]) => {
  const types = typeof expected === 'string' ? [expected] : expected
  const expectedTypes = types.map(normalizeJoseType)
  const quoted = types.map((type) => `'${type}'`).join(', ')

  // NOTE: the value is validated but not normalized, so that the header still holds the `typ` as it
  // was received, and re-encoding a parsed token does not change what it says.
  return z.string().refine((type) => expectedTypes.includes(normalizeJoseType(type)), {
    message: `Expected the media type to be ${quoted}`,
  })
}
