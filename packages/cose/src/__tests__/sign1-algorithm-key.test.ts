import { ed448 } from '@noble/curves/ed448.js'
import { ed25519 } from '@noble/curves/ed25519.js'
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

type SignatureScheme = {
  utils: { randomSecretKey: () => Uint8Array }
  getPublicKey: (secretKey: Uint8Array, ...args: never[]) => Uint8Array
  sign: (message: Uint8Array, secretKey: Uint8Array, ...args: never[]) => Uint8Array
  verify: (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array, ...args: never[]) => boolean
}

const ecdsa = { [Curve['P-256']]: p256, [Curve['P-384']]: p384, [Curve['P-521']]: p521 } as Record<number, typeof p256>
const eddsa = { [Curve.Ed25519]: ed25519, [Curve.Ed448]: ed448 } as Record<number, SignatureScheme>

const createKey = (curve: Curve) => {
  const eddsaScheme = eddsa[curve]
  if (eddsaScheme) {
    const d = eddsaScheme.utils.randomSecretKey()
    return CoseKey.create({ keyType: KeyType.Okp, curve, x: eddsaScheme.getPublicKey(d), d })
  }

  const d = ecdsa[curve].utils.randomSecretKey()
  // Uncompressed SEC1 point: 0x04 || x || y.
  const publicKey = ecdsa[curve].getPublicKey(d, false)
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
  sign: async ({ key, toBeSigned }) => {
    const curve = key.curve as Curve
    if (eddsa[curve]) return eddsa[curve].sign(toBeSigned, key.privateKey)
    return ecdsa[curve].sign(toBeSigned, key.privateKey, { format: 'compact' })
  },
  verify: async ({ key, toBeVerified, signature }) => {
    const curve = key.curve as Curve
    if (eddsa[curve]) return eddsa[curve].verify(signature, toBeVerified, key.publicKey)
    return ecdsa[curve].verify(signature, toBeVerified, key.publicKey, { lowS: false })
  },
}

const createSign1 = (algorithm: SignatureAlgorithm, signature?: Uint8Array) =>
  Sign1.create({
    protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, algorithm]]),
    unprotectedHeaders: new Map(),
    payload: stringToBytes('RFC 9864'),
    signature,
  })

describe('signature algorithms and the key they are used with', () => {
  test('the fully-specified algorithms have the values of RFC 9864 § 2.1 and § 2.2', () => {
    expect(SignatureAlgorithm.ESP256).toBe(-9)
    expect(SignatureAlgorithm.ESP384).toBe(-51)
    expect(SignatureAlgorithm.ESP512).toBe(-52)
    expect(SignatureAlgorithm.Ed25519).toBe(-19)
    expect(SignatureAlgorithm.Ed448).toBe(-53)
  })

  test.each([
    { algorithm: SignatureAlgorithm.ESP256, curve: Curve['P-256'], jwa: 'ES256', signatureLength: 64 },
    { algorithm: SignatureAlgorithm.ESP384, curve: Curve['P-384'], jwa: 'ES384', signatureLength: 96 },
    { algorithm: SignatureAlgorithm.ESP512, curve: Curve['P-521'], jwa: 'ES512', signatureLength: 132 },
    { algorithm: SignatureAlgorithm.Ed25519, curve: Curve.Ed25519, jwa: 'Ed25519', signatureLength: 64 },
    { algorithm: SignatureAlgorithm.Ed448, curve: Curve.Ed448, jwa: 'Ed448', signatureLength: 114 },
    { algorithm: SignatureAlgorithm.ES256, curve: Curve['P-256'], jwa: 'ES256', signatureLength: 64 },
    { algorithm: SignatureAlgorithm.EdDSA, curve: Curve.Ed25519, jwa: 'EdDSA', signatureLength: 64 },
    { algorithm: SignatureAlgorithm.EdDSA, curve: Curve.Ed448, jwa: 'EdDSA', signatureLength: 114 },
  ] as const)(
    'signs and verifies alg $algorithm with a key on curve $curve',
    async ({ algorithm, curve, jwa, signatureLength }) => {
      const key = createKey(curve)

      const signed = await createSign1(algorithm).sign({ signingKey: key, algorithm }, multiCurveContext)
      const decoded = Sign1.decode(signed.encode())

      expect(decoded.signature).toHaveLength(signatureLength)
      expect(decoded.algorithm).toBe(algorithm)
      expect(decoded.jwaAlgorithm).toBe(jwa)
      expect(await decoded.verifySignature({ key }, multiCurveContext)).toBe(true)
    }
  )

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
    { algorithm: SignatureAlgorithm.ESP256, curve: Curve.Ed25519 },
    { algorithm: SignatureAlgorithm.Ed25519, curve: Curve.Ed448 },
    { algorithm: SignatureAlgorithm.Ed448, curve: Curve.Ed25519 },
    { algorithm: SignatureAlgorithm.Ed25519, curve: Curve['P-256'] },
    // RFC 9053 § 2.1: ECDSA requires an EC2 key on P-256, P-384 or P-521.
    { algorithm: SignatureAlgorithm.ES256, curve: Curve.Ed25519 },
    // RFC 9053 § 2.2: EdDSA requires an OKP key on an EdDSA curve.
    { algorithm: SignatureAlgorithm.EdDSA, curve: Curve['P-256'] },
  ] as const)('rejects verifying alg $algorithm with a key on curve $curve', async ({ algorithm, curve }) => {
    const key = createKey(curve)
    // A signature that is valid for the key, so only the key check can reject it.
    const unsigned = createSign1(algorithm)
    const signature = await multiCurveContext.sign({ toBeSigned: unsigned.toBeSigned(), key, algorithm })
    const verify = vi.fn(multiCurveContext.verify)

    await expect(createSign1(algorithm, signature).verifySignature({ key }, { verify })).rejects.toThrow(
      CoseInvalidAlgorithmError
    )
    expect(verify).not.toHaveBeenCalled()
  })

  test.each([
    { algorithm: SignatureAlgorithm.ESP256, curve: Curve['P-384'], message: 'requires an EC2 key on curve P-256' },
    {
      algorithm: SignatureAlgorithm.ES256,
      curve: Curve.Ed25519,
      message: 'requires an EC2 key on curve P-256 or P-384 or P-521',
    },
    { algorithm: SignatureAlgorithm.Ed25519, curve: Curve['P-256'], message: 'requires an OKP key on curve Ed25519' },
  ] as const)('rejects signing alg $algorithm with a key on curve $curve', async ({ algorithm, curve, message }) => {
    const sign = vi.fn(multiCurveContext.sign)

    await expect(createSign1(algorithm).sign({ signingKey: createKey(curve), algorithm }, { sign })).rejects.toThrow(
      `Algorithm ${SignatureAlgorithm[algorithm]} ${message}`
    )
    expect(sign).not.toHaveBeenCalled()
  })

  test('rejects an EC2 key without a curve', async () => {
    const { x, y } = createKey(Curve['P-256'])
    const key = CoseKey.create({ keyType: KeyType.Ec, x, y })

    await expect(
      createSign1(SignatureAlgorithm.ES256, new Uint8Array(64)).verifySignature({ key }, multiCurveContext)
    ).rejects.toThrow(CoseInvalidAlgorithmError)
  })

  // RFC 9053 § 2.1 only suggests pairing the hash of ES256, ES384 and ES512 with a curve.
  test('accepts the polymorphic ES256 with a key on P-384', async () => {
    const key = createKey(Curve['P-384'])
    const signed = await createSign1(SignatureAlgorithm.ES256).sign(
      { signingKey: key, algorithm: SignatureAlgorithm.ES256 },
      multiCurveContext
    )

    expect(await signed.verifySignature({ key }, multiCurveContext)).toBe(true)
  })

  // A key is valid for every algorithm its key type and curve allow, whatever its own `alg`.
  test('accepts a key whose alg is ES256 for ESP256', async () => {
    const { x, y, d } = createKey(Curve['P-256'])
    const key = CoseKey.create({
      keyType: KeyType.Ec,
      curve: Curve['P-256'],
      x,
      y,
      d,
      algorithm: SignatureAlgorithm.ES256,
    })
    const signed = await createSign1(SignatureAlgorithm.ESP256).sign(
      { signingKey: key, algorithm: SignatureAlgorithm.ESP256 },
      multiCurveContext
    )

    expect(await signed.verifySignature({ key }, multiCurveContext)).toBe(true)
  })

  // RSA keys have no COSE key type in this package, so the RSA algorithms are left to the context.
  test('does not check the key for RS256', async () => {
    const verify = vi.fn(async () => false)

    await createSign1(SignatureAlgorithm.RS256, new Uint8Array(256)).verifySignature(
      { key: createKey(Curve['P-256']) },
      { verify }
    )

    expect(verify).toHaveBeenCalledOnce()
  })

  test('the fully-specified algorithms convert to their JWA names', () => {
    expect(coseKeyToJwkClaim.algorithm(SignatureAlgorithm.ESP256)).toBe('ES256')
    expect(coseKeyToJwkClaim.algorithm(SignatureAlgorithm.ESP384)).toBe('ES384')
    expect(coseKeyToJwkClaim.algorithm(SignatureAlgorithm.ESP512)).toBe('ES512')
    expect(coseKeyToJwkClaim.algorithm(SignatureAlgorithm.Ed25519)).toBe('Ed25519')
    expect(coseKeyToJwkClaim.algorithm(SignatureAlgorithm.Ed448)).toBe('Ed448')
    expect(CoseKey.create({ keyType: KeyType.Ec, algorithm: SignatureAlgorithm.ESP256 }).jwk.alg).toBe('ES256')
  })

  test('the JWA names convert to the COSE algorithms of the same name', () => {
    expect(jwkToCoseKey.alg('ES256')).toBe(SignatureAlgorithm.ES256)
    expect(jwkToCoseKey.alg('ES384')).toBe(SignatureAlgorithm.ES384)
    expect(jwkToCoseKey.alg('ES512')).toBe(SignatureAlgorithm.ES512)
    expect(jwkToCoseKey.alg('EdDSA')).toBe(SignatureAlgorithm.EdDSA)
    expect(jwkToCoseKey.alg('Ed25519')).toBe(SignatureAlgorithm.Ed25519)
    expect(jwkToCoseKey.alg('Ed448')).toBe(SignatureAlgorithm.Ed448)
    expect(coseKeyToJwkClaim.algorithm(SignatureAlgorithm.ES256)).toBe('ES256')
  })
})
