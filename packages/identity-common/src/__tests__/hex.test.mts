import { describe, expect, it } from 'vitest'
import { hex, hexDecode, hexEncode, IdentityCommonException } from '../../src'

describe('hex', () => {
  it('should encode and decode Uint8Array', () => {
    const input = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]) // "Hello"
    const encoded = hexEncode(input)
    const decoded = hexDecode(encoded)
    expect(decoded).toEqual(input)
  })

  it('should encode and decode using hex object API', () => {
    const input = new Uint8Array([0xff, 0xfe, 0xfd])
    const encoded = hex.encode(input)
    const decoded = hex.decode(encoded)
    expect(decoded).toEqual(input)
  })

  it('should handle odd-length hex strings by padding with leading zero', () => {
    const encoded = 'abc' // odd length
    const decoded = hexDecode(encoded)
    const reEncoded = hexEncode(decoded)
    expect(reEncoded).toBe('0abc')
  })

  it('should handle uppercase hex characters', () => {
    const input = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f])
    const encoded = hexEncode(input)
    const upperEncoded = encoded.toUpperCase()
    const decoded = hexDecode(upperEncoded)
    expect(decoded).toEqual(input)
  })

  it('should handle mixed case hex characters', () => {
    const input = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f])
    const mixedCase = '48656C6C6F' // mixed case version of "48656c6c6f"
    const decoded = hexDecode(mixedCase)
    expect(decoded).toEqual(input)
  })

  it('should handle empty input', () => {
    const input = new Uint8Array([])
    const encoded = hexEncode(input)
    expect(encoded).toBe('')
    const decoded = hexDecode(encoded)
    expect(decoded).toEqual(input)
  })

  it('should throw IdentityCommonException for invalid hex characters', () => {
    expect(() => hexDecode('xyz')).toThrow(IdentityCommonException)
    expect(() => hexDecode('48656g6c6f')).toThrow(IdentityCommonException)
  })

  it('should produce lowercase hex output', () => {
    const input = new Uint8Array([0xff, 0xfe, 0xfd])
    const encoded = hexEncode(input)
    expect(encoded).toBe('fffefd')
    expect(encoded).toBe(encoded.toLowerCase())
  })
})
