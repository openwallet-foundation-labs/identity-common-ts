import { describe, expect, it } from 'vitest'
import { JoseAlgorithmNotAllowedError } from '../error'
import { isJwaSignatureAlgorithm, isSymmetricSignatureAlgorithm, JwaSignatureAlgorithm } from '../jwa/algorithms'
import { assertKeyAllowedForSignatureAlgorithm } from '../jwa/key-compatibility'
import type { Jwk } from '../jwk/z-jwk'
import { parseJws } from '../jws/parse-jws'
import { assertJwsAlgorithmAllowed, verifyJwsSignature } from '../jws/verify-jws'
import { unsignedCompactJws } from './context'

/** Matches a thrown error by its class and a part of its message. */
const joseError = (type: { name: string }, message: string) =>
  expect.objectContaining({ name: type.name, message: expect.stringContaining(message) })

const keys = {
  oct: { kty: 'oct', k: 'c2VjcmV0' },
  rsa: { kty: 'RSA', n: 'bW9kdWx1cw', e: 'AQAB' },
  p256: { kty: 'EC', crv: 'P-256', x: 'eA', y: 'eQ' },
  p384: { kty: 'EC', crv: 'P-384', x: 'eA', y: 'eQ' },
  p521: { kty: 'EC', crv: 'P-521', x: 'eA', y: 'eQ' },
  secp256k1: { kty: 'EC', crv: 'secp256k1', x: 'eA', y: 'eQ' },
  ed25519: { kty: 'OKP', crv: 'Ed25519', x: 'eA' },
  ed448: { kty: 'OKP', crv: 'Ed448', x: 'eA' },
  x25519: { kty: 'OKP', crv: 'X25519', x: 'eA' },
} satisfies Record<string, Jwk>

type KeyName = keyof typeof keys

/**
 * The key type and curve each registered algorithm takes, written out here rather than read from
 * the tables in `jwa/algorithms`, so that a mistake in those tables is not repeated by the test.
 */
const expectedKeys: Record<JwaSignatureAlgorithm, { kty: string; crv?: string }> = {
  HS256: { kty: 'oct' },
  HS384: { kty: 'oct' },
  HS512: { kty: 'oct' },
  RS256: { kty: 'RSA' },
  RS384: { kty: 'RSA' },
  RS512: { kty: 'RSA' },
  PS256: { kty: 'RSA' },
  PS384: { kty: 'RSA' },
  PS512: { kty: 'RSA' },
  ES256: { kty: 'EC', crv: 'P-256' },
  ES384: { kty: 'EC', crv: 'P-384' },
  ES512: { kty: 'EC', crv: 'P-521' },
  ES256K: { kty: 'EC', crv: 'secp256k1' },
  EdDSA: { kty: 'OKP' },
  Ed25519: { kty: 'OKP', crv: 'Ed25519' },
  Ed448: { kty: 'OKP', crv: 'Ed448' },
}

const registeredAlgorithms = Object.values(JwaSignatureAlgorithm)

describe('assertKeyAllowedForSignatureAlgorithm', () => {
  describe('key type and curve', () => {
    const usableKeys: Array<{ alg: JwaSignatureAlgorithm; key: KeyName }> = [
      { alg: JwaSignatureAlgorithm.HS256, key: 'oct' },
      { alg: JwaSignatureAlgorithm.HS384, key: 'oct' },
      { alg: JwaSignatureAlgorithm.HS512, key: 'oct' },
      { alg: JwaSignatureAlgorithm.RS256, key: 'rsa' },
      { alg: JwaSignatureAlgorithm.RS384, key: 'rsa' },
      { alg: JwaSignatureAlgorithm.RS512, key: 'rsa' },
      { alg: JwaSignatureAlgorithm.PS256, key: 'rsa' },
      { alg: JwaSignatureAlgorithm.PS384, key: 'rsa' },
      { alg: JwaSignatureAlgorithm.PS512, key: 'rsa' },
      { alg: JwaSignatureAlgorithm.ES256, key: 'p256' },
      { alg: JwaSignatureAlgorithm.ES384, key: 'p384' },
      { alg: JwaSignatureAlgorithm.ES512, key: 'p521' },
      { alg: JwaSignatureAlgorithm.ES256K, key: 'secp256k1' },
      // `EdDSA` is polymorphic, so it takes a key of either Edwards curve
      { alg: JwaSignatureAlgorithm.EdDSA, key: 'ed25519' },
      { alg: JwaSignatureAlgorithm.EdDSA, key: 'ed448' },
      { alg: JwaSignatureAlgorithm.Ed25519, key: 'ed25519' },
      { alg: JwaSignatureAlgorithm.Ed448, key: 'ed448' },
    ]

    it('has a usable key for every registered signature algorithm', () => {
      expect(new Set(usableKeys.map(({ alg }) => alg))).toEqual(new Set(registeredAlgorithms))
    })

    it.each(usableKeys)('accepts the $key key for $alg', ({ alg, key }) => {
      expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk: keys[key], alg })).not.toThrow()
    })

    // One key of every other type for every algorithm: `HS256` over an RSA key is the key confusion
    // attack, the others are the same mistake in another direction.
    const keyOfType: Record<string, KeyName> = { oct: 'oct', RSA: 'rsa', EC: 'p256', OKP: 'ed25519' }
    const keysOfAnotherType = registeredAlgorithms.flatMap((alg) =>
      Object.entries(keyOfType)
        .filter(([kty]) => kty !== expectedKeys[alg].kty)
        .map(([kty, key]) => ({ alg, key, kty, expectedKty: expectedKeys[alg].kty }))
    )

    it.each(keysOfAnotherType)('rejects the $key key for $alg', ({ alg, key, kty, expectedKty }) => {
      expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk: keys[key], alg })).toThrow(
        joseError(
          JoseAlgorithmNotAllowedError,
          `Algorithm '${alg}' requires a key with kty '${expectedKty}', but the key has kty '${kty}'.`
        )
      )
    })

    // Every key of the right type but on another curve, for the algorithms that fix their curve
    const keysOnAnotherCurve = registeredAlgorithms.flatMap((alg) => {
      const { kty, crv } = expectedKeys[alg]
      if (!crv) return []

      return (Object.keys(keys) as KeyName[])
        .filter((key) => keys[key].kty === kty && 'crv' in keys[key] && keys[key].crv !== crv)
        .map((key) => ({ alg, key, crv: (keys[key] as { crv: string }).crv, expectedCrv: crv }))
    })

    it.each(keysOnAnotherCurve)('rejects the $key key for $alg', ({ alg, key, crv, expectedCrv }) => {
      expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk: keys[key], alg })).toThrow(
        joseError(
          JoseAlgorithmNotAllowedError,
          `Algorithm '${alg}' requires a key with crv '${expectedCrv}', but the key has crv '${crv}'.`
        )
      )
    })

    it('rejects an EC key without a curve for ES256', () => {
      expect(() =>
        assertKeyAllowedForSignatureAlgorithm({ jwk: { kty: 'EC', x: 'eA', y: 'eQ' }, alg: 'ES256' })
      ).toThrow(
        joseError(
          JoseAlgorithmNotAllowedError,
          `Algorithm 'ES256' requires a key with crv 'P-256', but the key has no crv.`
        )
      )
    })

    it('leaves the key type of an unregistered algorithm to the verification callback', () => {
      // ML-DSA is not one of the algorithms this package knows, and its keys have kty 'AKP'
      expect(() =>
        assertKeyAllowedForSignatureAlgorithm({ jwk: { kty: 'AKP', pub: 'cHVi' }, alg: 'ML-DSA-44' })
      ).not.toThrow()
    })
  })

  describe('the alg the key declares', () => {
    it('accepts a key that declares the alg of the token', () => {
      expect(() =>
        assertKeyAllowedForSignatureAlgorithm({ jwk: { ...keys.p256, alg: 'ES256' }, alg: 'ES256' })
      ).not.toThrow()
    })

    it('rejects a key that declares another alg of the same key type', () => {
      expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk: { ...keys.rsa, alg: 'RS256' }, alg: 'PS256' })).toThrow(
        joseError(JoseAlgorithmNotAllowedError, `The key declares alg 'RS256', but the token uses alg 'PS256'.`)
      )
    })

    it('rejects a key that declares another alg for an unregistered algorithm', () => {
      expect(() =>
        assertKeyAllowedForSignatureAlgorithm({ jwk: { kty: 'AKP', alg: 'ML-DSA-65' }, alg: 'ML-DSA-44' })
      ).toThrow(
        joseError(JoseAlgorithmNotAllowedError, `The key declares alg 'ML-DSA-65', but the token uses alg 'ML-DSA-44'.`)
      )
    })
  })

  describe('the use the key declares', () => {
    it('accepts a key that declares use sig', () => {
      expect(() =>
        assertKeyAllowedForSignatureAlgorithm({ jwk: { ...keys.p256, use: 'sig' }, alg: 'ES256' })
      ).not.toThrow()
    })

    it('rejects a key that declares use enc', () => {
      expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk: { ...keys.p256, use: 'enc' }, alg: 'ES256' })).toThrow(
        joseError(JoseAlgorithmNotAllowedError, `The key declares use 'enc' instead of 'sig'.`)
      )
    })

    it('rejects a key that declares a use that is not registered', () => {
      expect(() =>
        assertKeyAllowedForSignatureAlgorithm({ jwk: { ...keys.p256, use: 'signing' }, alg: 'ES256' })
      ).toThrow(joseError(JoseAlgorithmNotAllowedError, `The key declares use 'signing' instead of 'sig'.`))
    })

    it('rejects an encryption key for an unregistered algorithm', () => {
      expect(() =>
        assertKeyAllowedForSignatureAlgorithm({ jwk: { kty: 'AKP', use: 'enc' }, alg: 'ML-DSA-44' })
      ).toThrow(joseError(JoseAlgorithmNotAllowedError, `The key declares use 'enc' instead of 'sig'.`))
    })
  })

  describe('the key_ops the key declares', () => {
    it.each([[['verify']], [['sign']], [['sign', 'verify']], [['verify', 'encrypt']]])(
      'accepts a key with key_ops %j',
      (keyOps) => {
        expect(() =>
          assertKeyAllowedForSignatureAlgorithm({ jwk: { ...keys.p256, key_ops: keyOps }, alg: 'ES256' })
        ).not.toThrow()
      }
    )

    it('rejects a key whose key_ops are only for encryption', () => {
      expect(() =>
        assertKeyAllowedForSignatureAlgorithm({ jwk: { ...keys.p256, key_ops: ['encrypt', 'decrypt'] }, alg: 'ES256' })
      ).toThrow(
        joseError(
          JoseAlgorithmNotAllowedError,
          `The key declares key_ops 'encrypt', 'decrypt', which does not include 'sign' or 'verify'.`
        )
      )
    })

    it('rejects a key whose key_ops are empty', () => {
      expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk: { ...keys.p256, key_ops: [] }, alg: 'ES256' })).toThrow(
        joseError(JoseAlgorithmNotAllowedError, `which does not include 'sign' or 'verify'.`)
      )
    })
  })

  it('starts the error with the given errorMessage', () => {
    expect(() =>
      assertKeyAllowedForSignatureAlgorithm({
        jwk: keys.rsa,
        alg: 'ES256',
        errorMessage: 'Unable to verify the proof.',
      })
    ).toThrow(
      expect.objectContaining({ message: expect.stringMatching(/^Unable to verify the proof\. Algorithm 'ES256'/) })
    )
  })
})

describe('assertJwsAlgorithmAllowed', () => {
  const asymmetricAlgorithms = registeredAlgorithms.filter((alg) => !alg.startsWith('HS'))
  const symmetricAlgorithms = [JwaSignatureAlgorithm.HS256, JwaSignatureAlgorithm.HS384, JwaSignatureAlgorithm.HS512]

  it.each(asymmetricAlgorithms)('accepts %s when no algorithms are listed', (alg) => {
    expect(() => assertJwsAlgorithmAllowed({ alg })).not.toThrow()
  })

  it.each(symmetricAlgorithms)('rejects %s while symmetric algorithms are not allowed', (alg) => {
    expect(() => assertJwsAlgorithmAllowed({ alg })).toThrow(
      joseError(JoseAlgorithmNotAllowedError, `The JWS uses the symmetric algorithm '${alg}'.`)
    )
  })

  it('rejects a symmetric algorithm on the allowed list while symmetric algorithms are not allowed', () => {
    // Listing an algorithm does not opt in to what it implies: that is said separately
    expect(() => assertJwsAlgorithmAllowed({ alg: 'HS256', allowedAlgorithms: ['HS256'] })).toThrow(
      joseError(JoseAlgorithmNotAllowedError, `The JWS uses the symmetric algorithm 'HS256'.`)
    )
  })

  it('accepts a symmetric algorithm on the allowed list when symmetric algorithms are allowed', () => {
    expect(() =>
      assertJwsAlgorithmAllowed({ alg: 'HS512', allowedAlgorithms: ['HS512'], allowSymmetricAlgorithms: true })
    ).not.toThrow()
  })

  it('rejects an algorithm missing from the allowed list even when symmetric algorithms are allowed', () => {
    expect(() =>
      assertJwsAlgorithmAllowed({ alg: 'HS384', allowedAlgorithms: ['HS256'], allowSymmetricAlgorithms: true })
    ).toThrow(
      joseError(JoseAlgorithmNotAllowedError, `The JWS uses alg 'HS384', but the allowed algorithms are 'HS256'.`)
    )
  })

  it('rejects every algorithm when the allowed list is empty', () => {
    expect(() => assertJwsAlgorithmAllowed({ alg: 'ES256', allowedAlgorithms: [] })).toThrow(
      joseError(JoseAlgorithmNotAllowedError, `The JWS uses alg 'ES256', but the allowed algorithms are .`)
    )
  })

  it('starts the error with the given errorMessage', () => {
    expect(() => assertJwsAlgorithmAllowed({ alg: 'HS256', errorMessage: 'Unable to verify the proof.' })).toThrow(
      expect.objectContaining({ message: expect.stringMatching(/^Unable to verify the proof\. The JWS uses/) })
    )
  })
})

describe('isJwaSignatureAlgorithm and isSymmetricSignatureAlgorithm', () => {
  it('does not count none as a signature algorithm', () => {
    expect(isJwaSignatureAlgorithm('none')).toBe(false)
  })

  it('counts exactly the HMAC algorithms as symmetric', () => {
    expect(registeredAlgorithms.filter(isSymmetricSignatureAlgorithm)).toEqual(['HS256', 'HS384', 'HS512'])
  })
})

describe('verifyJwsSignature with the key the callback verified with', () => {
  const verifiedWith = (signerJwk: Jwk) => () => ({ verified: true as const, signerJwk })

  it('rejects a signature that the callback verified with an encryption key', async () => {
    const jws = parseJws({ jws: unsignedCompactJws({ alg: 'ES256' }, {}) })

    await expect(
      verifyJwsSignature({ jws, verifyJwsCallback: verifiedWith({ ...keys.p256, use: 'enc' }) })
    ).rejects.toThrow(
      joseError(
        JoseAlgorithmNotAllowedError,
        `Error during verification of the JWS. The key the JWS was verified with cannot be used with its algorithm. The key declares use 'enc' instead of 'sig'.`
      )
    )
  })

  it('rejects an ES384 token that the callback verified with a P-256 key', async () => {
    const jws = parseJws({ jws: unsignedCompactJws({ alg: 'ES384' }, {}) })

    await expect(verifyJwsSignature({ jws, verifyJwsCallback: verifiedWith(keys.p256) })).rejects.toThrow(
      joseError(
        JoseAlgorithmNotAllowedError,
        `Algorithm 'ES384' requires a key with crv 'P-384', but the key has crv 'P-256'.`
      )
    )
  })

  it('returns the signer with the key the callback verified with when the key fits the algorithm', async () => {
    const jws = parseJws({ jws: unsignedCompactJws({ alg: 'ES512' }, {}) })

    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: verifiedWith(keys.p521) })

    expect(signer).toEqual({ method: 'custom', alg: 'ES512', kid: undefined, publicJwk: keys.p521 })
  })
})
