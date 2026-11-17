import { timingSafeEqual } from 'node:crypto'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64url, hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { z } from 'zod'
import {
  CoseInvalidAlgorithmError,
  CoseKey,
  cborDecode,
  cborEncode,
  KeyType,
  Mac0,
  type Mac0Context,
  type Mac0EncodedStructure,
  MacAlgorithm,
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

// HMac-01 of the COSE WG examples (github.com/cose-wg/Examples, mac0-tests/HMac-01.json)
const hmac01 = Mac0.decode(
  hex.decode(
    'd18443a10105a054546869732069732074686520636f6e74656e742e5820a1a848d3471f9d61ee49018d244c824772f223ad4f935293f1789fc3a08d8c58'
  )
)
const hmac01KeyId = 'our-secret'
const hmac01K = base64url.decode('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg')

/**
 * A context that keeps the secret to itself, as a key management system does, and records the
 * calls it gets, so the keys passed to the library only have a `keyId`.
 */
function createKmsContext() {
  const calls: Array<Parameters<Mac0Context['authenticate']>[0]> = []
  const secret = (key: CoseKey) => {
    if (key.keyId !== hmac01KeyId) throw new Error(`Unknown key '${key.keyId}'`)
    return hmac01K
  }

  const context: Mac0Context = {
    authenticate: async (input) => {
      calls.push(input)
      return hmac(sha256, secret(input.key), input.toBeAuthenticated)
    },
    verify: async ({ key, tag, toBeAuthenticated }) =>
      timingSafeEqual(tag, hmac(sha256, secret(key), toBeAuthenticated)),
  }

  return { context, calls }
}

describe('mac0', () => {
  test('the MAC_structure has a zero-length external_aad when none is supplied (RFC 9052 6.3)', () => {
    expect(hex.encode(hmac01.toBeAuthenticated())).toBe(
      '84644d41433043a101054054546869732069732074686520636f6e74656e742e'
    )
  })

  test('authenticates and verifies with a key that only has a key id', async () => {
    const { context, calls } = createKmsContext()
    const key = CoseKey.create({ keyType: KeyType.Oct, keyId: hmac01KeyId })

    const mac0 = await Mac0.create({ protectedHeaders: hmac01.protectedHeaders, payload: hmac01.payload }).authenticate(
      { key, algorithm: MacAlgorithm.HS256 },
      context
    )

    expect(hex.encode(mac0.tag)).toBe(hex.encode(hmac01.tag))
    expect(calls).toEqual([expect.objectContaining({ key, algorithm: MacAlgorithm.HS256 })])
    expect(calls[0].key.k).toBeUndefined()
    await expect(hmac01.verifyAuthenticationCode({ key }, context)).resolves.toBe(true)
  })

  test('verifies a tag of an earlier version, which left external_aad out of the MAC_structure', async () => {
    const { context } = createKmsContext()
    const key = CoseKey.create({ keyType: KeyType.Oct, keyId: hmac01KeyId })
    const legacyTag = hmac(
      sha256,
      hmac01K,
      cborEncode(['MAC0', hmac01.protectedHeaders.encodedStructure, hmac01.payload])
    )
    const legacy = Mac0.create({ protectedHeaders: hmac01.protectedHeaders, payload: hmac01.payload, tag: legacyTag })

    await expect(legacy.verifyAuthenticationCode({ key }, context)).resolves.toBe(true)
    // Earlier versions put a supplied external_aad in the MAC_structure, so it never had this form.
    await expect(legacy.verifyAuthenticationCode({ key, externalAad: new Uint8Array() }, context)).resolves.toBe(false)
  })

  test('the algorithm passed to authenticate takes precedence over the alg of the key', async () => {
    const { context, calls } = createKmsContext()
    const key = CoseKey.create({ keyType: KeyType.Oct, keyId: hmac01KeyId, algorithm: MacAlgorithm.HS512 })

    await Mac0.create({ payload: hmac01.payload }).authenticate({ key, algorithm: MacAlgorithm.HS256 }, context)

    expect(calls).toEqual([expect.objectContaining({ algorithm: MacAlgorithm.HS256 })])
  })

  test('authenticate takes the algorithm from the key when none is passed', async () => {
    const { context, calls } = createKmsContext()
    const key = CoseKey.create({ keyType: KeyType.Oct, keyId: hmac01KeyId, algorithm: MacAlgorithm.HS384 })

    await Mac0.create({ payload: hmac01.payload }).authenticate({ key }, context)

    expect(calls).toEqual([expect.objectContaining({ algorithm: MacAlgorithm.HS384 })])
  })

  test('authenticate throws without an algorithm in the options or the key', async () => {
    const { context, calls } = createKmsContext()
    const key = CoseKey.create({ keyType: KeyType.Oct, keyId: hmac01KeyId })

    await expect(Mac0.create({ payload: hmac01.payload }).authenticate({ key }, context)).rejects.toThrow(
      CoseInvalidAlgorithmError
    )
    expect(calls).toEqual([])
  })

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
