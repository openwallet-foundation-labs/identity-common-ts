import { describe, expect, test } from 'vitest'
import { cborEncode } from '../cbor'
import { RegisteredCwtHeaderClaimKey } from '../cose/headers/defaults'
import { ProtectedHeaders } from '../cose/headers/protected-headers'
import { UnprotectedHeaders } from '../cose/headers/unprotected-headers'

const { KeyId, X5Chain } = RegisteredCwtHeaderClaimKey

describe('cose header claims', () => {
  test('a bstr kid is accepted and typed', () => {
    const kid = new Uint8Array([1, 2, 3])
    const headers = UnprotectedHeaders.create({ unprotectedHeaders: new Map([[KeyId, kid]]) })
    expect(headers.headers.get(KeyId)).toStrictEqual(kid)
  })

  test('a malformed kid ({ 4: undefined }) is rejected when decoding unprotected headers', () => {
    const bytes = cborEncode(new Map<number, unknown>([[KeyId, undefined]]))
    expect(() => UnprotectedHeaders.decode(bytes)).toThrow()
  })

  test('a malformed kid is rejected when decoding protected headers', () => {
    const innerMap = cborEncode(new Map<number, unknown>([[KeyId, undefined]]))
    expect(() => ProtectedHeaders.fromEncodedStructure(innerMap)).toThrow()
  })

  test('a non-bstr kid is rejected', () => {
    const bytes = cborEncode(new Map<number, unknown>([[KeyId, 'not-bytes']]))
    expect(() => UnprotectedHeaders.decode(bytes)).toThrow()
  })

  test('other header labels (e.g. x5chain) pass through untouched', () => {
    const chain = [new Uint8Array([9])]
    const headers = UnprotectedHeaders.create({ unprotectedHeaders: new Map([[X5Chain, chain]]) })
    expect(headers.headers.get(X5Chain)).toStrictEqual(chain)
    // No kid present is fine.
    expect(headers.headers.get(KeyId)).toBeUndefined()
  })
})
