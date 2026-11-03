import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { z } from 'zod'
import {
  CoseKey,
  cborDecode,
  cborEncode,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  Sign1,
  type Sign1EncodedStructure,
  SignatureAlgorithm,
  UnprotectedHeaders,
  zSign1Decoded,
  zSign1Encoded,
  zUint8Array,
} from '../../src'
import { sign1Context } from './context'
import { sign1TestVector01, sign1TestVector02 } from './vectors'

const cbor = hex.decode(
  'd28441a0a201260442313154546869732069732074686520636f6e74656e742e584087db0d2e5571843b78ac33ecb2830df7b6e0a4d5b7376de336b23c591c90c425317e56127fbe04370097ce347087b233bf722b64072beb4486bda4031d27244f'
)

describe('sign1', () => {
  test('parse', async () => {
    const sign1 = Sign1.decode(cbor)

    expect(sign1.unprotectedHeaders.headers?.has(RegisteredCwtHeaderClaimKey.Algorithm)).toBeTruthy()
    expect(sign1.unprotectedHeaders.headers?.has(RegisteredCwtHeaderClaimKey.KeyId)).toBeTruthy()
    expect(sign1.payload).toBeDefined()
    expect(sign1.signature).toBeDefined()

    expect(sign1.encode().entries()).toStrictEqual(cbor.entries())
  })

  ;[sign1TestVector01, sign1TestVector02].map(async (testVector) => {
    test(`${testVector.title} :: ${testVector.description}`, async () => {
      const key = CoseKey.fromJwk(testVector.key)

      const sign1 = Sign1.fromDecodedStructure({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: cborDecode<Map<number, unknown>>(
            hex.decode(testVector['sign1::sign'].protectedHeaders.cborHex)
          ),
        }),
        unprotectedHeaders: UnprotectedHeaders.decode(hex.decode(testVector['sign1::sign'].unprotectedHeaders.cborHex)),
        payload: hex.decode(testVector['sign1::sign'].payload),
        signature: cborDecode<Sign1>(hex.decode(testVector['sign1::sign'].expectedOutput.cborHex)).signature,
      })

      // The external AAD is not carried in the COSE structure, so it is supplied to every call that
      // builds the Sig_Structure: `toBeSigned`, `verifySignature` and `sign`.
      const externalAad = hex.decode(testVector['sign1::sign'].external)

      const tbsHex = hex.encode(sign1.toBeSigned({ externalAad }))

      expect(tbsHex).toStrictEqual(testVector['sign1::sign'].tbsHex.cborHex)

      const isValid = await sign1.verifySignature({ key, externalAad }, sign1Context)
      expect(isValid).toBe(true)

      // Verifying without it must not pass — for the vector that actually carries one, since an
      // empty external input is the same as none.
      if (externalAad.length > 0) {
        expect(await sign1.verifySignature({ key }, sign1Context)).toBe(false)
      }

      const sign1Resigned = Sign1.create({
        protectedHeaders: sign1.protectedHeaders,
        unprotectedHeaders: sign1.unprotectedHeaders,
        payload: sign1.payload,
      })

      const sign1ResignedWithSignature = await sign1Resigned.sign(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256, externalAad },
        sign1Context
      )

      const isValidAfterResign = await sign1ResignedWithSignature.verifySignature({ key, externalAad }, sign1Context)
      expect(isValidAfterResign).toBe(true)

      // Regression: signing used the AAD passed to `sign` while verification used one held on the
      // structure, so a signature made with an AAD did not verify against that same AAD.
      if (externalAad.length > 0) {
        expect(await sign1ResignedWithSignature.verifySignature({ key }, sign1Context)).toBe(false)
      }
    })
  })

  test('subclass decode respects subclass encodingSchema and returns subclass instance', () => {
    const zCustomSign1Decoded = zSign1Decoded.extend({
      payload: zUint8Array.nullable().refine((p) => p !== null && p.length >= 5, { message: 'Payload too short' }),
    })

    class CustomSign1 extends Sign1 {
      public static override get encodingSchema() {
        return z.codec(zSign1Encoded, zCustomSign1Decoded, {
          encode: (decoded) =>
            [
              decoded.protectedHeaders.encodedStructure,
              decoded.unprotectedHeaders.encodedStructure,
              decoded.payload,
              decoded.signature,
            ] satisfies Sign1EncodedStructure,
          decode: ([protectedHeaders, unprotected, payload, signature]) => ({
            protectedHeaders: ProtectedHeaders.fromEncodedStructure(protectedHeaders),
            unprotectedHeaders: UnprotectedHeaders.fromEncodedStructure(unprotected),
            payload,
            signature,
          }),
        })
      }
    }

    // Tagged input with valid payload
    const decodedTagged = CustomSign1.decode(cbor)
    expect(decodedTagged).toBeInstanceOf(CustomSign1)
    expect(decodedTagged.payload).toBeDefined()

    // Untagged input with valid payload
    const untaggedCbor = (cborDecode(cbor) as Sign1).encodedStructure
    const decodedUntagged = CustomSign1.decode(cborEncode(untaggedCbor))
    expect(decodedUntagged).toBeInstanceOf(CustomSign1)

    // Subclass error validation with short payload (< 5 bytes)
    const shortPayloadSign1 = Sign1.create({
      protectedHeaders: new Map(),
      unprotectedHeaders: new Map(),
      payload: new Uint8Array([1, 2]),
      signature: new Uint8Array([3, 4]),
    })
    const shortTaggedBytes = shortPayloadSign1.encode()
    const shortUntaggedBytes = cborEncode(shortPayloadSign1.encodedStructure)

    expect(() => CustomSign1.decode(shortTaggedBytes)).toThrow('Error decoding CustomSign1')
    expect(() => CustomSign1.decode(shortUntaggedBytes)).toThrow('Error decoding CustomSign1')
  })
})
