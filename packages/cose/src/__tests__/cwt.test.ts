import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { cborEncode } from '../cbor'
import {
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
})
