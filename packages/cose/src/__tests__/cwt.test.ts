import { hex } from '@owf/identity-common'
import { Tag } from 'cbor-x'
import { describe, expect, test } from 'vitest'
import { CborDecodeError, cborEncode } from '../cbor'
import {
  CosePayloadInvalidStructureError,
  Cwt,
  Mac0,
  MacAlgorithm,
  ProtectedHeaders,
  RegisteredCwtClaimKey,
  RegisteredCwtHeaderClaimKey,
  Sign1,
  SignatureAlgorithm,
} from '../cose'
import { mac0Context, macKey, sign1Context, signKey } from './context'

describe('Cwt', () => {
  describe('Sign1 based CWT', () => {
    test('create and encode', async () => {
      const payload = new Map([[RegisteredCwtClaimKey.Issuer, 'coap://as.example']])

      const cwt = Cwt.create({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
        }),
        unprotectedHeaders: new Map(),
        payload: cborEncode(payload),
      })

      expect(cwt.payload).toBeDefined()
      expect(cwt.protectedHeaders).toBeDefined()
    })

    test('sign and verify with Sign1 context', async () => {
      const payload = hex.decode('a10150636f61703a2f2f61732e6578616d706c65') // {"1":"coap://as.example"}

      const sign1 = Sign1.create({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
        }),
        unprotectedHeaders: new Map(),
        payload,
      })

      const signed = await sign1.sign({ signingKey: signKey, algorithm: SignatureAlgorithm.ES256 }, sign1Context)
      const token = signed.encode()

      const cwt = Cwt.fromToken(token)
      expect(cwt.payload).toStrictEqual(payload)

      const isValid = await cwt.verifySignature({ key: signKey }, sign1Context)
      expect(isValid).toBe(true)
    })

    test('fromToken and access properties', async () => {
      const payload = hex.decode('a10150636f61703a2f2f61732e6578616d706c65')

      const sign1 = Sign1.create({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
        }),
        unprotectedHeaders: new Map(),
        payload,
      })

      const signed = await sign1.sign({ signingKey: signKey, algorithm: SignatureAlgorithm.ES256 }, sign1Context)
      const token = signed.encode()

      const cwt = Cwt.fromToken(token)

      expect(cwt.asSign1).toBeDefined()
      expect(cwt.protectedHeaders).toBeDefined()
      expect(cwt.unprotectedHeaders).toBeDefined()
      expect(cwt.signatureOrTag).toBeDefined()
      expect(cwt.signatureOrTag).toStrictEqual(signed.signature)
    })
  })

  describe('Mac0 based CWT', () => {
    test('create and encode', async () => {
      const payload = new Map([[RegisteredCwtClaimKey.Issuer, 'coap://as.example']])

      const cwt = Cwt.create({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, MacAlgorithm.HS256]]),
        }),
        unprotectedHeaders: new Map(),
        payload: cborEncode(payload),
      })

      expect(cwt.payload).toBeDefined()
      expect(cwt.protectedHeaders).toBeDefined()
    })

    test('authenticate and verify with Mac0 context', async () => {
      const payload = hex.decode('a10150636f61703a2f2f61732e6578616d706c65')

      const mac0 = Mac0.create({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, MacAlgorithm.HS256]]),
        }),
        unprotectedHeaders: new Map(),
        payload,
      })

      const authenticated = await mac0.authenticate({ key: macKey, algorithm: MacAlgorithm.HS256 }, mac0Context)
      const token = authenticated.encode()

      const cwt = Cwt.fromToken(token)
      expect(cwt.payload).toStrictEqual(payload)

      const isValid = await cwt.verifyAuthenticationCode({ key: macKey }, mac0Context)
      expect(isValid).toBe(true)
    })

    test('fromToken and access properties', async () => {
      const payload = hex.decode('a10150636f61703a2f2f61732e6578616d706c65')

      const mac0 = Mac0.create({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, MacAlgorithm.HS256]]),
        }),
        unprotectedHeaders: new Map(),
        payload,
      })

      const authenticated = await mac0.authenticate({ key: macKey, algorithm: MacAlgorithm.HS256 }, mac0Context)
      const token = authenticated.encode()

      const cwt = Cwt.fromToken(token)

      expect(cwt.asMac0).toBeDefined()
      expect(cwt.protectedHeaders).toBeDefined()
      expect(cwt.unprotectedHeaders).toBeDefined()
      expect(cwt.signatureOrTag).toBeDefined()
      expect(cwt.signatureOrTag).toStrictEqual(authenticated.tag)
    })
  })

  describe('fromToken with malformed input', () => {
    test('should throw a CborDecodeError describing the input when it is not valid cbor', () => {
      // Trailing bytes after a complete cbor value
      const token = new Uint8Array([0x0f, 0x74, 0xa1])

      expect(() => Cwt.fromToken(token)).toThrow(CborDecodeError)
      expect(() => Cwt.fromToken(token)).toThrow(/Unable to decode 3 bytes as CBOR/)
    })

    test.each([
      ['a number', cborEncode(15), /decoded the number value '15'/],
      ['a text string', cborEncode('hello'), /decoded the text string 'hello'/],
      ['a byte string', cborEncode(new Uint8Array([1, 2, 3])), /decoded a byte string of 3 bytes/],
      ['a map', cborEncode(new Map([['a', 1]])), /decoded an untagged map with 1 entry/],
      ['null', cborEncode(null), /decoded null/],
      [
        'an untagged cose array',
        cborEncode([new Uint8Array([0xa0]), new Map(), new Uint8Array([1, 2]), new Uint8Array([3, 4])]),
        /decoded an untagged array with 4 elements/,
      ],
      ['a value with an unrelated tag', cborEncode(new Tag([1, 2], 999)), /decoded a CBOR value tagged with tag 999/],
      [
        'a cwt tagged (tag 61) value',
        cborEncode(new Tag([1, 2], 61)),
        /decoded a CBOR value tagged with tag 61 \(the CWT tag, which must be unwrapped first\)/,
      ],
    ])('should reject %s that is valid cbor but not a cose token', (_name, token, expected) => {
      expect(() => Cwt.fromToken(token)).toThrow(CosePayloadInvalidStructureError)
      expect(() => Cwt.fromToken(token)).toThrow(expected)
    })
  })
})
