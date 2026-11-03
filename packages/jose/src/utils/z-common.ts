import { addValidationIssue, zBase64Url } from '@owf/identity-common'
import z from 'zod'

/**
 * A StringOrURI: a string value that is compared as a case-sensitive string, and that must be a URI
 * whenever it contains a `:`.
 *
 * The URI form is not enforced: OpenID4VP client identifiers such as `x509_san_dns:example.com`
 * are used as `iss` and `aud`, but `_` is not allowed in a URI scheme (RFC 3986 section 3.1).
 *
 * @see https://www.rfc-editor.org/rfc/rfc7519#section-2
 */
export const zStringOrUri = z.string({
  error: `Expected a StringOrURI: a string, which must be a URI when it contains a ':'`,
})

/**
 * A compact serialization: `partCount` base64url parts separated by `.`, of which only the ones at
 * `emptyParts` may be empty. Anything else gives an `invalid_format` issue with `format` as context.
 */
export function zCompactSerialization(format: string, partCount: number, emptyParts: ReadonlyArray<number> = []) {
  return z.string().superRefine((value, ctx) => {
    const parts = value.split('.')
    const isCompact =
      parts.length === partCount &&
      parts.every((part, index) => (part !== '' || emptyParts.includes(index)) && zBase64Url.safeParse(part).success)

    if (!isCompact) {
      addValidationIssue(ctx, {
        code: 'invalid_format',
        message: `Not a valid compact ${format.toUpperCase()}`,
        context: { format },
      })
    }
  })
}
