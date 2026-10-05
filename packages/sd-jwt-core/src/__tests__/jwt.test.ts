import Crypto from 'node:crypto'
import { describe, expect, test } from 'vitest'
import { Jwt } from '../jwt'
import type { Signer, Verifier } from '../types'
import { base64urlEncode, JwtTimeClaimException, SDJWTException } from '../utils'

describe('JWT', () => {
  test('create', async () => {
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })

    expect(jwt.header).toEqual({ alg: 'EdDSA' })
    expect(jwt.payload).toEqual({ foo: 'bar' })
  })

  test('returns decoded JWT when correct JWT string is provided', () => {
    const jwt = `${base64urlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${base64urlEncode(
      JSON.stringify({ sub: '1234567890', name: 'John Doe' })
    )}.signature`
    const result = Jwt.decodeJWT(jwt)
    expect(result).toEqual({
      header: { alg: 'HS256', typ: 'JWT' },
      payload: { sub: '1234567890', name: 'John Doe' },
      signature: 'signature',
    })
  })

  test('throws an error when JWT string is not correctly formed', () => {
    const jwt = 'abc.def'
    expect(() => Jwt.decodeJWT(jwt)).toThrow('Invalid JWT as input')
  })

  test('throws an error when JWT parts are missing', () => {
    const jwt = `${base64urlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}`
    expect(() => Jwt.decodeJWT(jwt)).toThrow('Invalid JWT as input')
  })

  test('set', async () => {
    const jwt = new Jwt()
    jwt.setHeader({ alg: 'EdDSA' })
    jwt.setPayload({ foo: 'bar' })

    expect(jwt.header).toEqual({ alg: 'EdDSA' })
    expect(jwt.payload).toEqual({ foo: 'bar' })
  })

  test('sign', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })

    const encodedJwt = await jwt.sign(testSigner)
    expect(typeof encodedJwt).toBe('string')
  })

  test('verify', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })

    const encodedJwt = await jwt.sign(testSigner)
    const newJwt = Jwt.fromEncode(encodedJwt)
    const verified = await newJwt.verify(testVerifier)
    expect(verified).toStrictEqual({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })
    try {
      await newJwt.verify(() => false)
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException)
    }
  })

  test('encode', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })

    const encodedJwt = await jwt.sign(testSigner)
    const newJwt = Jwt.fromEncode(encodedJwt)
    const newEncodedJwt = newJwt.encodeJwt()
    expect(newEncodedJwt).toBe(encodedJwt)
  })

  test('decode failed', () => {
    expect(() => Jwt.fromEncode('asfasfas')).toThrow()
  })

  test('encode failed', async () => {
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
    })

    try {
      jwt.encodeJwt()
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException)
    }
  })

  test('getUnsignedToken failed', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
    })

    try {
      await jwt.sign(testSigner)
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException)
    }
  })

  test('wrong encoded field', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
      encoded: 'asfasfafaf.dfasfafafasf', // it has to be 3 parts
    })

    try {
      await jwt.sign(testSigner)
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException)
    }
  })

  test('verify failed no signature', async () => {
    const { publicKey } = Crypto.generateKeyPairSync('ed25519')
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })

    try {
      await jwt.verify(testVerifier)
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException)
    }
  })

  test('verify with issuance date in the future', async () => {
    const { publicKey } = Crypto.generateKeyPairSync('ed25519')
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { iat: 1100 },
    })

    const error = await jwt.verify(testVerifier, { currentDate: 1000 }).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(JwtTimeClaimException)
    expect(error).toMatchObject({
      message: 'Verify Error: JWT is not yet valid',
      code: 'JWT_NOT_YET_VALID',
      details: { claim: 'iat', value: 1100, currentDate: 1000, skewSeconds: 0 },
    })
  })

  test('verify with not before in the future', async () => {
    const { publicKey } = Crypto.generateKeyPairSync('ed25519')
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { nbf: 1100 },
    })

    const error = await jwt.verify(testVerifier, { currentDate: 1000 }).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(JwtTimeClaimException)
    expect(error).toMatchObject({
      message: 'Verify Error: JWT is not yet valid',
      code: 'JWT_NOT_YET_VALID',
      details: { claim: 'nbf', value: 1100, currentDate: 1000, skewSeconds: 0 },
    })
  })

  test('verify with expired', async () => {
    const { publicKey } = Crypto.generateKeyPairSync('ed25519')
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { exp: 1000 },
    })

    const error = await jwt.verify(testVerifier, { currentDate: 1100 }).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(JwtTimeClaimException)
    expect(error).toBeInstanceOf(SDJWTException)
    expect(error).toMatchObject({
      name: 'JwtTimeClaimException',
      message: 'Verify Error: JWT is expired',
      code: 'JWT_EXPIRED',
      details: { claim: 'exp', value: 1000, currentDate: 1100, skewSeconds: 0 },
    })
  })

  test('verify with expired reports the allowed skew in the details', async () => {
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { exp: 1000 },
    })

    const error = await jwt.verify(async () => true, { currentDate: 1100, skewSeconds: 30 }).catch((e: unknown) => e)
    expect((error as JwtTimeClaimException).details).toEqual({
      claim: 'exp',
      value: 1000,
      currentDate: 1100,
      skewSeconds: 30,
    })
  })

  test('verify with skew', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519')
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { exp: Math.floor(Date.now() / 1000) - 1 },
    })

    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }

    await jwt.sign(testSigner)
    await jwt.verify(testVerifier, { skewSeconds: 2 })
  })

  test('verify with expectedIssuer', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { iss: 'https://issuer.example.com' },
    })
    await jwt.sign(testSigner)

    // matching string
    await expect(jwt.verify(testVerifier, { expectedIssuer: 'https://issuer.example.com' })).resolves.toBeDefined()

    // matching array
    await expect(
      jwt.verify(testVerifier, { expectedIssuer: ['https://other.example.com', 'https://issuer.example.com'] })
    ).resolves.toBeDefined()

    // mismatching string
    await expect(jwt.verify(testVerifier, { expectedIssuer: 'https://other.example.com' })).rejects.toThrow(
      'Verify Error: Invalid issuer'
    )

    // missing iss claim
    const jwtNoIss = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })
    await jwtNoIss.sign(testSigner)
    await expect(jwtNoIss.verify(testVerifier, { expectedIssuer: 'https://issuer.example.com' })).rejects.toThrow(
      'Verify Error: Invalid issuer'
    )
  })

  test('verify with expectedSubject', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { sub: 'user-123' },
    })
    await jwt.sign(testSigner)

    // matching string
    await expect(jwt.verify(testVerifier, { expectedSubject: 'user-123' })).resolves.toBeDefined()

    // matching array
    await expect(jwt.verify(testVerifier, { expectedSubject: ['user-456', 'user-123'] })).resolves.toBeDefined()

    // mismatching string
    await expect(jwt.verify(testVerifier, { expectedSubject: 'user-456' })).rejects.toThrow(
      'Verify Error: Invalid subject'
    )

    // missing sub claim
    const jwtNoSub = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })
    await jwtNoSub.sign(testSigner)
    await expect(jwtNoSub.verify(testVerifier, { expectedSubject: 'user-123' })).rejects.toThrow(
      'Verify Error: Invalid subject'
    )
  })

  test('verify with maxAgeSeconds', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { iat: 1000 },
    })
    await jwt.sign(testSigner)

    // within maxAge
    await expect(jwt.verify(testVerifier, { currentDate: 1050, maxAgeSeconds: 60 })).resolves.toBeDefined()

    // exactly at limit
    await expect(jwt.verify(testVerifier, { currentDate: 1060, maxAgeSeconds: 60 })).resolves.toBeDefined()

    // exceeded maxAge
    await expect(jwt.verify(testVerifier, { currentDate: 1061, maxAgeSeconds: 60 })).rejects.toMatchObject({
      message: 'Verify Error: JWT is too old',
      code: 'JWT_TOO_OLD',
      details: { claim: 'iat', value: 1000, currentDate: 1061, skewSeconds: 0, maxAgeSeconds: 60 },
    })

    // exceeded maxAge but saved by skew
    await expect(
      jwt.verify(testVerifier, { currentDate: 1065, maxAgeSeconds: 60, skewSeconds: 10 })
    ).resolves.toBeDefined()

    // missing iat claim
    const jwtNoIat = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    })
    await jwtNoIat.sign(testSigner)
    await expect(jwtNoIat.verify(testVerifier, { currentDate: 1000, maxAgeSeconds: 60 })).rejects.toThrow(
      'Verify Error: JWT iat claim is missing'
    )
  })

  test('verify with expectedVct', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519')
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey)
      return Buffer.from(sig).toString('base64url')
    }
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
    }

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { vct: 'https://credentials.example.com/identity_credential' },
    })
    await jwt.sign(testSigner)

    // matching string
    await expect(
      jwt.verify(testVerifier, { expectedVct: 'https://credentials.example.com/identity_credential' })
    ).resolves.toBeDefined()

    // matching array
    await expect(
      jwt.verify(testVerifier, {
        expectedVct: ['https://other.example.com', 'https://credentials.example.com/identity_credential'],
      })
    ).resolves.toBeDefined()

    // mismatch
    await expect(jwt.verify(testVerifier, { expectedVct: 'https://other.example.com' })).rejects.toThrow(
      'Verify Error: Invalid VCT'
    )
  })
})
