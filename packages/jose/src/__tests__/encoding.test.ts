import { base64, base64url } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { decodeJwt } from '../jwt/decode-jwt'
import { unsignedCompactJws } from './context'

/**
 * The guarantees these tests protect are the reason every decode goes through
 * `@owf/identity-common`: two byte sequences that decode to the same header would be two tokens that
 * are treated as one.
 */
describe('strict decoding', () => {
  const header = { alg: 'ES256' }
  const payload = { iss: 'https://example.com' }

  const encodeJson = (value: unknown) => new TextEncoder().encode(JSON.stringify(value))

  it('decodes a well-formed token', () => {
    const { header: decodedHeader, payload: decodedPayload } = decodeJwt({ jwt: unsignedCompactJws(header, payload) })

    expect(decodedHeader).toEqual(header)
    expect(decodedPayload).toEqual(payload)
  })

  // The signature is handed to a verification callback without being decoded here, so the alphabet
  // is the only thing that says it is a signature at all.
  it('rejects a signature that is not base64url', () => {
    const jwt = `${base64url.encode(encodeJson(header))}.${base64url.encode(encodeJson(payload))}.not a signature`

    expect(() => decodeJwt({ jwt })).toThrow('the signature of a compact JWS must be base64url')
  })

  it('rejects a header encoded with the standard base64 alphabet', () => {
    // This header encodes to `+` in the standard alphabet and to `-` in the base64url one, so the
    // two encodings of the very same header are different strings.
    const headerWithTilde = { alg: 'ES256', kid: '~~a' }
    const standardBase64Header = base64.encode(encodeJson(headerWithTilde))
    expect(standardBase64Header).toContain('+')
    expect(base64url.encode(encodeJson(headerWithTilde))).toContain('-')

    const jwt = `${standardBase64Header}.${base64url.encode(encodeJson(payload))}.c2ln`
    // Rejected as a malformed compact JWS: `+` is not in the base64url alphabet, so the part is not
    // an encoded header at all, which `parseJws` reports before anything tries to decode it.
    expect(() => decodeJwt({ jwt })).toThrow('the protected header of a compact JWS must be base64url')
  })

  it('rejects a padded header', () => {
    const paddedHeader = `${base64url.encode(encodeJson(header))}==`
    const jwt = `${paddedHeader}.${base64url.encode(encodeJson(payload))}.c2ln`

    expect(() => decodeJwt({ jwt })).toThrow('the protected header of a compact JWS must be base64url')
  })

  it('rejects a payload that is not valid UTF-8', () => {
    // 0xff is never a valid UTF-8 byte, and would decode to U+FFFD with a lenient decoder
    const invalidUtf8Payload = base64url.encode(new Uint8Array([0x7b, 0x22, 0x61, 0x22, 0x3a, 0xff, 0x7d]))
    const jwt = `${base64url.encode(encodeJson(header))}.${invalidUtf8Payload}.c2ln`

    expect(() => decodeJwt({ jwt })).toThrow('not valid base64url encoded JSON')
  })

  it('rejects a header that is a JSON value other than an object', () => {
    const jwt = `${base64url.encode(encodeJson(['ES256']))}.${base64url.encode(encodeJson(payload))}.c2ln`

    expect(() => decodeJwt({ jwt })).toThrow('not a JSON object')
  })

  it('rejects a token that does not have three parts', () => {
    expect(() => decodeJwt({ jwt: 'a.b' })).toThrow('exactly three parts')
    expect(() => decodeJwt({ jwt: 'a.b.c.d' })).toThrow('exactly three parts')
  })

  it('rejects a token without a payload', () => {
    const jwt = `${base64url.encode(encodeJson(header))}..c2ln`

    expect(() => decodeJwt({ jwt })).toThrow('does not carry a payload')
  })

  it('does not include the token in the error', () => {
    const secret = 'c2VjcmV0LXZhbHVlLXRoYXQtc2hvdWxkLW5vdC1sZWFr'
    const jwt = `${secret}.${base64url.encode(encodeJson(payload))}.c2ln`

    expect(() => decodeJwt({ jwt })).toThrow()
    try {
      decodeJwt({ jwt })
    } catch (error) {
      expect((error as Error).message).not.toContain(secret)
    }
  })
})
