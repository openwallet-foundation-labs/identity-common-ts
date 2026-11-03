import { p256, p384, p521 } from '@noble/curves/nist.js'
import { stringToBytes } from '@owf/identity-common'
import { describe, expect, test, vi } from 'vitest'
import {
  CoseInvalidAlgorithmError,
  CoseKey,
  Curve,
  coseKeyToJwkClaim,
  jwkToCoseKey,
  KeyType,
  RegisteredCwtHeaderClaimKey,
  Sign1,
  type Sign1Context,
  SignatureAlgorithm,
} from '../cose'

// RFC 9864 § 2.1 defines ESP256 (-9), ESP384 (-51) and ESP512 (-52): ECDSA with the curve fixed by
// the algorithm, producing the same signatures as ES256, ES384 and ES512 on that curve.

const curves = {
  [Curve['P-256']]: p256,
  [Curve['P-384']]: p384,
  [Curve['P-521']]: p521,
} as Record<Curve, typeof p256>

const createKey = (curve: Curve) => {
  const ecdsa = curves[curve]
  const d = ecdsa.utils.randomSecretKey()
  // Uncompressed SEC1 point: 0x04 || x || y.
  const publicKey = ecdsa.getPublicKey(d, false)
  const coordinateLength = (publicKey.length - 1) / 2

  return CoseKey.create({
    keyType: KeyType.Ec,
    curve,
    x: publicKey.slice(1, 1 + coordinateLength),
    y: publicKey.slice(1 + coordinateLength),
    d,
  })
}

// Picks the curve, and with it the hash, from the key, as a context that ignores `algorithm` would.
const multiCurveContext: Sign1Context = {
  sign: async ({ key, toBeSigned }) =>
    curves[key.curve as Curve].sign(toBeSigned, key.privateKey, { format: 'compact' }),
  verify: async ({ key, toBeVerified, signature }) =>
    curves[key.curve as Curve].verify(signature, toBeVerified, key.publicKey, { lowS: false }),
}

const createSign1 = (algorithm: SignatureAlgorithm) =>
  Sign1.create({
    protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, algorithm]]),
    unprotectedHeaders: new Map(),
    payload: stringToBytes('RFC 9864'),
  })

describe('fully-specified ECDSA algorithms (RFC 9864 § 2.1)', () => {
  test('have the registered values', () => {
    expect(SignatureAlgorithm.ESP256).toBe(-9)
    expect(SignatureAlgorithm.ESP384).toBe(-51)
    expect(SignatureAlgorithm.ESP512).toBe(-52)
  })

  test.each([
    { algorithm: SignatureAlgorithm.ESP256, curve: Curve['P-256'], jwa: 'ES256', signatureLength: 64 },
    { algorithm: SignatureAlgorithm.ESP384, curve: Curve['P-384'], jwa: 'ES384', signatureLength: 96 },
    { algorithm: SignatureAlgorithm.ESP512, curve: Curve['P-521'], jwa: 'ES512', signatureLength: 132 },
  ] as const)('signs and verifies $jwa with alg $algorithm', async ({ algorithm, curve, jwa, signatureLength }) => {
    const key = createKey(curve)

    const signed = await createSign1(algorithm).sign({ signingKey: key, algorithm }, multiCurveContext)
    const decoded = Sign1.decode(signed.encode())

    expect(decoded.signature).toHaveLength(signatureLength)
    expect(decoded.algorithm).toBe(algorithm)
    expect(decoded.jwaAlgorithm).toBe(jwa)
    expect(await decoded.verifySignature({ key }, multiCurveContext)).toBe(true)
  })

  test('passes the fully-specified algorithm to the verify callback', async () => {
    const key = createKey(Curve['P-256'])
    const signed = await createSign1(SignatureAlgorithm.ESP256).sign(
      { signingKey: key, algorithm: SignatureAlgorithm.ESP256 },
      multiCurveContext
    )
    const verify = vi.fn(multiCurveContext.verify)

    await signed.verifySignature({ key }, { verify })

    expect(verify).toHaveBeenCalledWith(expect.objectContaining({ algorithm: SignatureAlgorithm.ESP256 }))
  })

  test.each([
    { algorithm: SignatureAlgorithm.ESP256, curve: Curve['P-384'] },
    { algorithm: SignatureAlgorithm.ESP384, curve: Curve['P-256'] },
    { algorithm: SignatureAlgorithm.ESP512, curve: Curve['P-384'] },
  ] as const)('rejects verifying alg $algorithm with a key on curve $curve', async ({ algorithm, curve }) => {
    const key = createKey(curve)
    // A signature that is valid for the key, so only the curve check can reject it.
    const unsigned = createSign1(algorithm)
    const sign1 = Sign1.create({
      protectedHeaders: unsigned.protectedHeaders,
      unprotectedHeaders: unsigned.unprotectedHeaders,
      payload: unsigned.payload,
      signature: await multiCurveContext.sign({ toBeSigned: unsigned.toBeSigned(), key, algorithm }),
    })
    const verify = vi.fn(multiCurveContext.verify)

    await expect(sign1.verifySignature({ key }, { verify })).rejects.toThrow(CoseInvalidAlgorithmError)
    expect(verify).not.toHaveBeenCalled()
  })

  test('rejects signing alg ESP256 with a key on P-384', async () => {
    const sign = vi.fn(multiCurveContext.sign)

    await expect(
      createSign1(SignatureAlgorithm.ESP256).sign(
        { signingKey: createKey(Curve['P-384']), algorithm: SignatureAlgorithm.ESP256 },
        { sign }
      )
    ).rejects.toThrow('Algorithm ESP256 requires an EC key on curve P-256')
    expect(sign).not.toHaveBeenCalled()
  })

  test('rejects alg ESP256 with a key that is not an EC key', async () => {
    const key = CoseKey.fromJwk({ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' })
    const sign1 = Sign1.create({
      protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ESP256]]),
      unprotectedHeaders: new Map(),
      payload: stringToBytes('RFC 9864'),
      signature: new Uint8Array(64),
    })

    await expect(sign1.verifySignature({ key }, multiCurveContext)).rejects.toThrow(CoseInvalidAlgorithmError)
  })

  // ES256 is polymorphic in COSE (RFC 9864 § 2.1, deprecated in § 4.2.2), so the curve of the key is
  // not checked for it.
  test('does not check the curve of the key for the polymorphic ES256', async () => {
    const key = createKey(Curve['P-384'])
    const signed = await createSign1(SignatureAlgorithm.ES256).sign(
      { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
      multiCurveContext
    )

    expect(await signed.verifySignature({ key }, multiCurveContext)).toBe(true)
  })

  test('convert to the JWA ES256, ES384 and ES512', () => {
    expect(coseKeyToJwkClaim.algorithm(SignatureAlgorithm.ESP256)).toBe('ES256')
    expect(coseKeyToJwkClaim.algorithm(SignatureAlgorithm.ESP384)).toBe('ES384')
    expect(coseKeyToJwkClaim.algorithm(SignatureAlgorithm.ESP512)).toBe('ES512')
    expect(CoseKey.create({ keyType: KeyType.Ec, algorithm: SignatureAlgorithm.ESP256 }).jwk.alg).toBe('ES256')
  })

  test('are not what the JWA ES256, ES384 and ES512 convert to', () => {
    expect(jwkToCoseKey.alg('ES256')).toBe(SignatureAlgorithm.ES256)
    expect(jwkToCoseKey.alg('ES384')).toBe(SignatureAlgorithm.ES384)
    expect(jwkToCoseKey.alg('ES512')).toBe(SignatureAlgorithm.ES512)
    expect(coseKeyToJwkClaim.algorithm(SignatureAlgorithm.ES256)).toBe('ES256')
  })
})
