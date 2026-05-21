import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import {
  CoseKey,
  cborDecode,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  Sign1,
  SignatureAlgorithm,
  UnprotectedHeaders,
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
        protectedHeaders: ProtectedHeaders.fromDecodedStructure(
          cborDecode(hex.decode(testVector['sign1::sign'].protectedHeaders.cborHex))
        ),
        unprotectedHeaders: UnprotectedHeaders.decode(hex.decode(testVector['sign1::sign'].unprotectedHeaders.cborHex)),
        payload: hex.decode(testVector['sign1::sign'].payload),
        signature: cborDecode<Sign1>(hex.decode(testVector['sign1::sign'].expectedOutput.cborHex)).signature,
      })

      sign1.externalAad = hex.decode(testVector['sign1::sign'].external)

      const tbsHex = hex.encode(sign1.toBeSigned)

      expect(tbsHex).toStrictEqual(testVector['sign1::sign'].tbsHex.cborHex)

      const isValid = await sign1.verifySignature({ key }, sign1Context)
      expect(isValid).toBeTruthy()

      const sign1Resigned = Sign1.create({
        protectedHeaders: sign1.protectedHeaders,
        unprotectedHeaders: sign1.unprotectedHeaders,
        payload: sign1.payload,
        externalAad: sign1.externalAad,
      })

      const sign1ResignedWithSignature = await sign1Resigned.sign(
        { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
        sign1Context
      )

      const isValidAfterResign = await sign1ResignedWithSignature.verifySignature({ key }, sign1Context)
      expect(isValidAfterResign).toBeTruthy()
    })
  })
})
