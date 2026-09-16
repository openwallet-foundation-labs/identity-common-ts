import { describe, expect, it } from 'vitest'
import {
  base64,
  base64UrlToUint8Array,
  base64url,
  base64urlDecode,
  base64urlEncode,
  bytesToString,
  stringToBytes,
  uint8ArrayToBase64Url,
} from '../base64url'

describe('base64url', () => {
  it('should encode and decode strings', () => {
    const input = 'Hello, World!'
    const encoded = base64urlEncode(input)
    const decoded = base64urlDecode(encoded)
    expect(decoded).toBe(input)
  })

  it('should handle URL-safe encoding', () => {
    const input = 'subjects?_d'
    const encoded = base64urlEncode(input)
    expect(encoded).not.toContain('+')
    expect(encoded).not.toContain('/')
    expect(encoded).not.toContain('=')
    expect(base64urlDecode(encoded)).toBe(input)
  })

  it('should encode and decode Uint8Array', () => {
    const input = new Uint8Array([72, 101, 108, 108, 111])
    const encoded = uint8ArrayToBase64Url(input)
    const decoded = base64UrlToUint8Array(encoded)
    expect(decoded).toEqual(input)
  })

  it('should produce URL-safe base64 from Uint8Array', () => {
    const input = new Uint8Array([0xff, 0xfe, 0xfd])
    const encoded = uint8ArrayToBase64Url(input)
    expect(encoded).not.toContain('+')
    expect(encoded).not.toContain('/')
  })

  it('should round-trip non-ASCII strings', () => {
    const input = 'Jöhn Dœ 🦋 日本'
    expect(base64urlDecode(base64urlEncode(input))).toBe(input)
  })

  it('should reject invalid characters, padding and length', () => {
    expect(() => base64url.decode('ab+/')).toThrow('Invalid base64url string: contains invalid characters')
    expect(() => base64url.decode('YQ==')).toThrow('Invalid base64url string: contains invalid characters')
    expect(() => base64url.decode('abcde')).toThrow('Invalid base64url string: invalid length')
  })
})

describe('base64', () => {
  it('should encode with padding, and decode with or without padding', () => {
    for (const length of [0, 1, 2, 3, 4, 5]) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 97 + 251) & 0xff)
      const encoded = base64.encode(bytes)
      expect(encoded.length % 4).toBe(0)
      expect(base64.decode(encoded)).toEqual(bytes)
      expect(base64.decode(encoded.replace(/=+$/, ''))).toEqual(bytes)
    }
  })

  it('should use the same alphabet as base64url apart from the last two characters', () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf])
    expect(base64.encode(bytes)).toBe('+/+/')
    expect(base64url.encode(bytes)).toBe('-_-_')
  })

  it('should reject invalid characters', () => {
    expect(() => base64.decode('ab-_')).toThrow('Invalid base64 string: contains invalid characters')
  })
})

describe('bytesToString', () => {
  // `"` followed by an invalid UTF-8 byte and `"`
  const invalidUtf8 = new Uint8Array([0x22, 0xff, 0x22])

  it('should decode UTF-8 and round-trip with stringToBytes', () => {
    const input = 'Jöhn Dœ 🦋'
    expect(bytesToString(stringToBytes(input))).toBe(input)
  })

  it('should replace invalid UTF-8 by default', () => {
    expect(bytesToString(invalidUtf8)).toBe('"�"')
  })

  it('should throw on invalid UTF-8 when fatal is set', () => {
    expect(() => bytesToString(invalidUtf8, { fatal: true })).toThrow('Invalid UTF-8 byte sequence')
    expect(() => base64urlDecode(base64url.encode(invalidUtf8), { fatal: true })).toThrow('Invalid UTF-8 byte sequence')
  })

  it('should keep a leading byte order mark', () => {
    expect(bytesToString(new Uint8Array([0xef, 0xbb, 0xbf, 0x61]))).toBe('﻿a')
  })
})
