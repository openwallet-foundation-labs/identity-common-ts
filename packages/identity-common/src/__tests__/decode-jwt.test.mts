import { describe, expect, it } from 'vitest'
import { base64url, base64urlDecodeJson, base64urlEncode } from '../base64url'
import { decodeJwt } from '../decode-jwt'

describe('decodeJwt', () => {
  it('should decode a JWT into header, payload, and signature', () => {
    const header = { alg: 'ES256', typ: 'JWT' }
    const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 }
    const jwt = `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(payload))}.signature`

    const result = decodeJwt(jwt)
    expect(result.header).toEqual(header)
    expect(result.payload).toEqual(payload)
    expect(result.signature).toBe('signature')
  })

  it('should throw an error for invalid JWT format', () => {
    expect(() => decodeJwt('not.a.valid.jwt')).toThrow('Invalid JWT as input')
    expect(() => decodeJwt('onlyonepart')).toThrow('Invalid JWT as input')
  })

  it('should throw a generic error for invalid base64url, UTF-8 or JSON', () => {
    const header = base64urlEncode(JSON.stringify({ alg: 'ES256' }))
    // `{"a":"` followed by an invalid UTF-8 sequence (0xc3 0x28) and `"}`
    const invalidUtf8 = base64url.encode(new Uint8Array([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d]))

    expect(() => decodeJwt(`${header}.${invalidUtf8}.sig`)).toThrow('Invalid JWT as input')
    expect(() => decodeJwt(`${header}.${base64urlEncode('{not json')}.sig`)).toThrow('Invalid JWT as input')
    expect(() => decodeJwt(`${header}.not+base64url.sig`)).toThrow('Invalid JWT as input')
    expect(() => decodeJwt(`${invalidUtf8}.${header}.sig`)).toThrow('Invalid JWT as input')
  })

  it('should decode with custom generic types', () => {
    const header = { alg: 'RS256', kid: 'key-1' }
    const payload = { iss: 'https://example.com', exp: 9999999999 }
    const jwt = `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(payload))}.sig`

    const result = decodeJwt<{ alg: string; kid: string }, { iss: string; exp: number }>(jwt)
    expect(result.header.kid).toBe('key-1')
    expect(result.payload.iss).toBe('https://example.com')
  })
})

describe('base64urlDecodeJson', () => {
  it('should decode base64url encoded JSON', () => {
    expect(base64urlDecodeJson(base64urlEncode(JSON.stringify({ name: 'Jöhn 🦋' })))).toEqual({ name: 'Jöhn 🦋' })
  })

  it('should reject invalid UTF-8 instead of replacing it', () => {
    const invalidUtf8 = base64url.encode(new Uint8Array([0x22, 0xff, 0x22]))
    expect(() => base64urlDecodeJson(invalidUtf8)).toThrow('Invalid base64url encoded JSON')
  })

  it('should reject invalid JSON and invalid base64url', () => {
    expect(() => base64urlDecodeJson(base64urlEncode('{not json'))).toThrow('Invalid base64url encoded JSON')
    expect(() => base64urlDecodeJson('not+base64url')).toThrow('Invalid base64url encoded JSON')
  })
})
