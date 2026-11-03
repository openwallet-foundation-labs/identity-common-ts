// The only place this package decodes JOSE parts, strictly, through `@owf/identity-common`. Don't decode
// elsewhere: two encodings of the same header would be two tokens that are treated as one.

import { base64url, base64urlDecodeJson, base64urlEncode, bytesToString } from '@owf/identity-common'
import { JoseNotSupportedError, JoseParseError } from '../error'

/**
 * Decodes a base64url encoded JSON object, such as a JWS protected header.
 *
 * @throws JoseParseError if the input is not valid base64url, not valid UTF-8, not valid JSON, or
 *   is a JSON value other than an object.
 */
export function decodeBase64UrlJsonObject(encoded: string, name: string): Record<string, unknown> {
  let decoded: unknown
  try {
    decoded = base64urlDecodeJson(encoded)
  } catch (error) {
    throw new JoseParseError(`Unable to decode the ${name}, it is not valid base64url encoded JSON`, { cause: error })
  }

  if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
    throw new JoseParseError(`Unable to decode the ${name}, it is not a JSON object`)
  }

  return decoded as Record<string, unknown>
}

/**
 * Decodes a base64url encoded value into bytes.
 *
 * @throws JoseParseError if the input is not valid base64url.
 */
export function decodeBase64UrlBytes(encoded: string, name: string): Uint8Array {
  try {
    return base64url.decode(encoded)
  } catch (error) {
    throw new JoseParseError(`Unable to decode the ${name}, it is not valid base64url`, { cause: error })
  }
}

/**
 * The payload of a JWS with `b64` false (RFC 7797), as it appears in the signing input. That is a
 * string, so a payload that is not valid UTF-8 is not supported.
 *
 * @throws JoseNotSupportedError if the payload is not valid UTF-8.
 */
export function decodeUnencodedPayload(payload: Uint8Array): string {
  try {
    return bytesToString(payload, { fatal: true })
  } catch (error) {
    throw new JoseNotSupportedError(`An unencoded payload ('b64' is false) that is not valid UTF-8 is not supported.`, {
      cause: error,
    })
  }
}

/**
 * Why an unencoded payload (`b64` false) cannot be carried in a compact serialization, or `undefined`
 * when it can: only printable ASCII other than '.' (%x20-2D and %x2F-7E) is allowed.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7797#section-5.2
 */
export function unencodedCompactPayloadIssue(payload: string): string | undefined {
  if (payload.includes('.')) {
    return `The payload is unencoded ('b64' is false) and contains a '.', which RFC 7797 section 5.2 does not allow in a compact serialization, where it separates the parts.`
  }

  if (!/^[\x20-\x7e]*$/.test(payload)) {
    return `The payload is unencoded ('b64' is false) and contains a character outside printable ASCII, which RFC 7797 section 5.2 does not allow in a compact serialization.`
  }

  return undefined
}

/** Encodes a JSON value the way a JOSE part is encoded: compact JSON, base64url, no padding. */
export function encodeBase64UrlJson(value: unknown): string {
  return base64urlEncode(JSON.stringify(value))
}
