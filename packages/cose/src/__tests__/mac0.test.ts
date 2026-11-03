import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { z } from 'zod'
import {
  cborDecode,
  cborEncode,
  Mac0,
  type Mac0EncodedStructure,
  ProtectedHeaders,
  type ProtectedHeadersEncodedStructure,
  UnprotectedHeaders,
  type UnprotectedHeadersStructure,
  zMac0Decoded,
  zMac0Encoded,
  zUint8Array,
} from '../../src'

const cbor =
  'd18441a0a1010554546869732069732074686520636f6e74656e742e5820176dce14c1e57430c13658233f41dc89aa4fa0ff9b8783f23b0ef51ca6b026bc'

describe('mac0', () => {
  test('parse', () => {
    const mac0 = Mac0.decode(hex.decode(cbor))

    expect(mac0.unprotectedHeaders.headers).toBeDefined()
    expect(mac0.payload).toBeDefined()
    expect(mac0.tag).toBeDefined()
  })

  test('subclass decode respects subclass encodingSchema and returns subclass instance', () => {
    const zCustomMac0Decoded = zMac0Decoded.extend({
      payload: zUint8Array.nullable().refine((p) => p !== null && p.length >= 5, { message: 'Payload too short' }),
    })

    class CustomMac0 extends Mac0 {
      public static override get encodingSchema() {
        return z.codec(zMac0Encoded, zCustomMac0Decoded, {
          encode: ({ protectedHeaders, unprotectedHeaders, payload, tag }) =>
            [
              protectedHeaders.encodedStructure,
              unprotectedHeaders.encodedStructure,
              payload,
              tag,
            ] satisfies Mac0EncodedStructure,
          decode: ([protectedHeadersBytes, unprotectedHeadersMap, payload, tag]) => ({
            protectedHeaders: ProtectedHeaders.fromEncodedStructure(
              protectedHeadersBytes as ProtectedHeadersEncodedStructure
            ),
            unprotectedHeaders: UnprotectedHeaders.fromEncodedStructure(
              unprotectedHeadersMap as UnprotectedHeadersStructure
            ),
            payload,
            tag,
          }),
        })
      }
    }

    // Tagged input with valid payload
    const decodedTagged = CustomMac0.decode(hex.decode(cbor))
    expect(decodedTagged).toBeInstanceOf(CustomMac0)
    expect(decodedTagged.payload).toBeDefined()

    // Untagged input with valid payload
    const untaggedCbor = (cborDecode(hex.decode(cbor)) as Mac0).encodedStructure
    const decodedUntagged = CustomMac0.decode(cborEncode(untaggedCbor))
    expect(decodedUntagged).toBeInstanceOf(CustomMac0)

    // Subclass error validation with short payload (< 5 bytes)
    const shortPayloadMac0 = Mac0.create({
      protectedHeaders: new Map(),
      unprotectedHeaders: new Map(),
      payload: new Uint8Array([1, 2]),
      tag: new Uint8Array([3, 4]),
    })
    const shortTaggedBytes = shortPayloadMac0.encode()
    const shortUntaggedBytes = cborEncode(shortPayloadMac0.encodedStructure)

    expect(() => CustomMac0.decode(shortTaggedBytes)).toThrow('Error decoding CustomMac0')
    expect(() => CustomMac0.decode(shortUntaggedBytes)).toThrow('Error decoding CustomMac0')
  })
})
