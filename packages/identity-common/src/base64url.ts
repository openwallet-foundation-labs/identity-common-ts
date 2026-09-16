import { IdentityCommonException } from './identity-common-exception'

/**
 * Encoding helpers, built in layers on top of each other:
 *
 * 1. bytes <-> base64 / base64url (`base64`, `base64url`)
 * 2. bytes <-> UTF-8 string (`stringToBytes`, `bytesToString`)
 * 3. string <-> base64url (`base64urlEncode`, `base64urlDecode`)
 * 4. JSON <-> base64url (`base64urlDecodeJson`)
 *
 * The UTF-8 layer uses `TextEncoder` and `TextDecoder`, which must be available in the environment.
 */

// ==================== Layer 1: bytes <-> base64 / base64url ====================

type Base64Alphabet = 'base64' | 'base64url'

const ALPHABETS: Record<Base64Alphabet, string> = {
  base64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  base64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
}

// base64 allows (optional) padding, base64url as used in JOSE does not
const VALID_INPUT: Record<Base64Alphabet, RegExp> = {
  base64: /^[A-Za-z0-9+/]*={0,2}$/,
  base64url: /^[A-Za-z0-9_-]*$/,
}

const encodeBase64 = (bytes: Uint8Array, alphabet: Base64Alphabet): string => {
  const chars = ALPHABETS[alphabet]
  let result = ''
  let i = 0

  for (; i + 2 < bytes.length; i += 3) {
    const chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]
    result += chars[(chunk >> 18) & 63] + chars[(chunk >> 12) & 63] + chars[(chunk >> 6) & 63] + chars[chunk & 63]
  }

  const remaining = bytes.length - i
  if (remaining > 0) {
    const chunk = (bytes[i] << 16) | (remaining === 2 ? bytes[i + 1] << 8 : 0)
    result += chars[(chunk >> 18) & 63] + chars[(chunk >> 12) & 63]
    if (remaining === 2) result += chars[(chunk >> 6) & 63]
    if (alphabet === 'base64') result += remaining === 2 ? '=' : '=='
  }

  return result
}

const decodeBase64 = (input: string, alphabet: Base64Alphabet): Uint8Array => {
  if (!VALID_INPUT[alphabet].test(input)) {
    throw new IdentityCommonException(`Invalid ${alphabet} string: contains invalid characters`)
  }

  const chars = ALPHABETS[alphabet]
  const unpadded = input.replace(/=+$/, '')
  // A single trailing character can never encode a full byte
  if (unpadded.length % 4 === 1) {
    throw new IdentityCommonException(`Invalid ${alphabet} string: invalid length`)
  }

  const bytes = new Uint8Array((unpadded.length * 3) >> 2)
  let byteIndex = 0
  for (let i = 0; i < unpadded.length; i += 4) {
    const a = chars.indexOf(unpadded[i])
    const b = chars.indexOf(unpadded[i + 1])
    const c = i + 2 < unpadded.length ? chars.indexOf(unpadded[i + 2]) : 0
    const d = i + 3 < unpadded.length ? chars.indexOf(unpadded[i + 3]) : 0

    bytes[byteIndex++] = (a << 2) | (b >> 4)
    if (i + 2 < unpadded.length) bytes[byteIndex++] = ((b & 15) << 4) | (c >> 2)
    if (i + 3 < unpadded.length) bytes[byteIndex++] = ((c & 3) << 6) | d
  }

  return bytes
}

export const base64 = {
  encode: (bytes: Uint8Array): string => encodeBase64(bytes, 'base64'),
  decode: (input: string): Uint8Array => decodeBase64(input, 'base64'),
}

export const base64url = {
  encode: (bytes: Uint8Array): string => encodeBase64(bytes, 'base64url'),
  decode: (input: string): Uint8Array => decodeBase64(input, 'base64url'),
}

export const uint8ArrayToBase64Url = base64url.encode

export const base64UrlToUint8Array = base64url.decode

// ==================== Layer 2: bytes <-> UTF-8 string ====================

export type BytesToStringOptions = {
  /**
   * Throw an `IdentityCommonException` when the bytes are not valid UTF-8, instead of replacing
   * invalid sequences with U+FFFD. Use this whenever the decoded string is processed further,
   * e.g. parsed as JSON, so different byte sequences can't decode to the same string.
   *
   * @default false
   */
  fatal?: boolean
}

export const stringToBytes = (input: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(input)

export const bytesToString = (bytes: Uint8Array, options?: BytesToStringOptions): string => {
  // ignoreBOM keeps a leading byte order mark in the output, so the string represents the exact bytes
  const decoder = new TextDecoder('utf-8', { fatal: options?.fatal ?? false, ignoreBOM: true })
  try {
    return decoder.decode(bytes)
  } catch {
    throw new IdentityCommonException('Invalid UTF-8 byte sequence')
  }
}

export const concatBytes = (...byteArrays: Array<Uint8Array>) => {
  const result = new Uint8Array(byteArrays.reduce((n, a) => n + a.byteLength, 0))
  let offset = 0
  for (const entry of byteArrays) {
    result.set(entry, offset)
    offset += entry.byteLength
  }
  return result
}

export const compareBytes = (lhs: Uint8Array, rhs: Uint8Array) => {
  if (lhs === rhs) return true
  if (lhs.byteLength !== rhs.byteLength) return false
  return lhs.every((b, i) => b === rhs[i])
}

// ==================== Layer 3: string <-> base64url ====================

export const base64urlEncode = (input: string): string => base64url.encode(stringToBytes(input))

export const base64urlDecode = (input: string, options?: BytesToStringOptions): string =>
  bytesToString(base64url.decode(input), options)

// ==================== Layer 4: JSON <-> base64url ====================

/**
 * Decode a base64url encoded UTF-8 JSON value, e.g. a JWT header or payload.
 *
 * Bytes that are not valid UTF-8 are rejected instead of being decoded to a different string, and
 * every failure (invalid base64url, invalid UTF-8 or invalid JSON) throws the same
 * `IdentityCommonException` without exposing details of the input.
 */
export const base64urlDecodeJson = <T = unknown>(input: string): T => {
  try {
    return JSON.parse(base64urlDecode(input, { fatal: true })) as T
  } catch {
    throw new IdentityCommonException('Invalid base64url encoded JSON')
  }
}
