import { describe, expect, test } from 'vitest'
import { CoseKey, Mac0, MacAlgorithm, Sign1, SignatureAlgorithm } from '../../src'
import { mac0Context, sign1Context } from './context'

const key = CoseKey.fromJwk({
  kty: 'EC',
  crv: 'P-256',
  x: 'eBUFGSPkdYwJ9TqYpcNxhAyr-A8wlWzrLQJppSi3x0E',
  y: 'Jnf8v4steg6Gr4IEFpg_xcM5xdHKdngbQN9ERJbJvl8',
  d: 'hGc90b8KMIjIpZos81yEFbOMc0Ww3k5ZNWICzDwtFV4',
  alg: 'ES256',
})

const payload = new Uint8Array([1, 2, 3, 4, 5])
const detachedPayload = new Uint8Array([6, 7, 8, 9, 10])

describe('Sign1 - detached payload', () => {
  describe('create()', () => {
    test('creates Sign1 with embedded payload', () => {
      const sign1 = Sign1.create({ payload })
      expect(sign1.payload).toEqual(payload)
    })

    test('creates Sign1 with detached payload by passing null', () => {
      const sign1 = Sign1.create({ payload: null })
      expect(sign1.payload).toBeNull()
    })

    test('does NOT set detachedPayload as the payload field', () => {
      const sign1 = Sign1.create({ payload: null })
      expect(sign1.payload).toBeNull()
      expect(sign1.payload).not.toEqual(detachedPayload)
    })
  })

  describe('toBeSigned()', () => {
    test('returns toBeSigned bytes for embedded payload', () => {
      const sign1 = Sign1.create({ payload })
      const tbs = sign1.toBeSigned()
      expect(tbs).toBeInstanceOf(Uint8Array)
      expect(tbs.length).toBeGreaterThan(0)
    })

    test('returns toBeSigned bytes when detachedPayload is supplied for a null-payload Sign1', () => {
      const sign1 = Sign1.create({ payload: null })
      const tbs = sign1.toBeSigned({ detachedPayload })
      expect(tbs).toBeInstanceOf(Uint8Array)
      expect(tbs.length).toBeGreaterThan(0)
    })

    test('embedded and detached produce identical TBS for the same payload bytes', () => {
      const sign1Embedded = Sign1.create({ payload })
      const sign1Detached = Sign1.create({ payload: null })
      expect(sign1Embedded.toBeSigned()).toEqual(sign1Detached.toBeSigned({ detachedPayload: payload }))
    })

    test('throws when Sign1 has an embedded payload and detachedPayload is also passed', () => {
      const sign1 = Sign1.create({ payload })
      expect(() => sign1.toBeSigned({ detachedPayload })).toThrow(
        'Cannot provide detachedPayload when the Sign1 already contains an embedded payload'
      )
    })

    test('throws when payload is null and no detachedPayload is passed', () => {
      const sign1 = Sign1.create({ payload: null })
      expect(() => sign1.toBeSigned()).toThrow()
    })
  })

  describe('sign()', () => {
    test('signs with embedded payload', async () => {
      const sign1 = Sign1.create({ payload })
      await sign1.sign({ signingKey: key, algorithm: SignatureAlgorithm.ES256 }, sign1Context)
      expect(sign1.signature.length).toBeGreaterThan(0)
    })

    test('signs with detachedPayload passed to sign() — payload field stays null', async () => {
      const sign1 = Sign1.create({ payload: null })
      await sign1.sign({ signingKey: key, algorithm: SignatureAlgorithm.ES256, detachedPayload }, sign1Context)
      expect(sign1.payload).toBeNull()
      expect(sign1.signature.length).toBeGreaterThan(0)
    })

    test('throws when Sign1 has embedded payload and detachedPayload is also passed to sign()', async () => {
      const sign1 = Sign1.create({ payload })
      await expect(
        sign1.sign({ signingKey: key, algorithm: SignatureAlgorithm.ES256, detachedPayload }, sign1Context)
      ).rejects.toThrow('Cannot provide detachedPayload when the Sign1 already contains an embedded payload')
    })

    test('throws when payload is null and no detachedPayload is passed to sign()', async () => {
      const sign1 = Sign1.create({ payload: null })
      await expect(sign1.sign({ signingKey: key, algorithm: SignatureAlgorithm.ES256 }, sign1Context)).rejects.toThrow()
    })
  })

  describe('verifySignature()', () => {
    test('verifies embedded payload Sign1', async () => {
      const sign1 = Sign1.create({ payload })
      await sign1.sign({ signingKey: key, algorithm: SignatureAlgorithm.ES256 }, sign1Context)
      const isValid = await sign1.verifySignature({ key }, sign1Context)
      expect(isValid).toBe(true)
    })

    test('ctx.verify receives the correct pre-computed toBeSigned bytes for detached payload', async () => {
      let capturedToBeVerified: Uint8Array | undefined

      const trackingContext = {
        ...sign1Context,
        verify: async (options: Parameters<typeof sign1Context.verify>[0]) => {
          capturedToBeVerified = options.toBeVerified
          return true
        },
      }

      const sign1 = Sign1.create({ payload: null })
      await sign1.sign({ signingKey: key, algorithm: SignatureAlgorithm.ES256, detachedPayload }, sign1Context)
      await sign1.verifySignature({ key, detachedPayload }, trackingContext)

      // The bytes passed to ctx.verify must match what toBeSigned() produces directly
      expect(capturedToBeVerified).toEqual(sign1.toBeSigned({ detachedPayload }))
    })

    test('throws when Sign1 has embedded payload and detachedPayload is passed to verifySignature()', async () => {
      const sign1 = Sign1.create({ payload })
      await sign1.sign({ signingKey: key, algorithm: SignatureAlgorithm.ES256 }, sign1Context)

      await expect(sign1.verifySignature({ key, detachedPayload }, sign1Context)).rejects.toThrow(
        'Cannot provide detachedPayload when the Sign1 already contains an embedded payload'
      )
    })
  })
})

describe('Mac0 - detached payload', () => {
  const macKey = new Uint8Array(32).fill(0xab)

  describe('create()', () => {
    test('creates Mac0 with embedded payload', () => {
      const mac0 = Mac0.create({ payload })
      expect(mac0.payload).toEqual(payload)
    })

    test('creates Mac0 with detached payload by passing null', () => {
      const mac0 = Mac0.create({ payload: null })
      expect(mac0.payload).toBeNull()
    })

    test('does NOT set detachedPayload as the payload field', () => {
      const mac0 = Mac0.create({ payload: null })
      expect(mac0.payload).toBeNull()
      expect(mac0.payload).not.toEqual(detachedPayload)
    })
  })

  describe('toBeAuthenticated()', () => {
    test('returns toBeAuthenticated bytes for embedded payload', () => {
      const mac0 = Mac0.create({ payload })
      const tba = mac0.toBeAuthenticated()
      expect(tba).toBeInstanceOf(Uint8Array)
      expect(tba.length).toBeGreaterThan(0)
    })

    test('returns toBeAuthenticated bytes when detachedPayload is supplied for a null-payload Mac0', () => {
      const mac0 = Mac0.create({ payload: null })
      const tba = mac0.toBeAuthenticated({ detachedPayload })
      expect(tba).toBeInstanceOf(Uint8Array)
      expect(tba.length).toBeGreaterThan(0)
    })

    test('embedded and detached produce identical TBA for the same payload bytes', () => {
      const mac0Embedded = Mac0.create({ payload })
      const mac0Detached = Mac0.create({ payload: null })
      expect(mac0Embedded.toBeAuthenticated()).toEqual(mac0Detached.toBeAuthenticated({ detachedPayload: payload }))
    })

    test('throws when Mac0 has an embedded payload and detachedPayload is also passed', () => {
      const mac0 = Mac0.create({ payload })
      expect(() => mac0.toBeAuthenticated({ detachedPayload })).toThrow(
        'Cannot provide detachedPayload when the Mac0 already contains an embedded payload'
      )
    })

    test('throws when payload is null and no detachedPayload is passed', () => {
      const mac0 = Mac0.create({ payload: null })
      expect(() => mac0.toBeAuthenticated()).toThrow()
    })
  })

  describe('authenticate()', () => {
    test('authenticates with embedded payload', async () => {
      const mac0 = Mac0.create({ payload })
      await mac0.authenticate({ key: macKey, algorithm: MacAlgorithm.HS256 }, mac0Context)
      expect(mac0.tag.length).toBeGreaterThan(0)
    })

    test('authenticates with detachedPayload passed to authenticate() — payload field stays null', async () => {
      const mac0 = Mac0.create({ payload: null })
      await mac0.authenticate({ key: macKey, detachedPayload, algorithm: MacAlgorithm.HS256 }, mac0Context)
      expect(mac0.payload).toBeNull()
      expect(mac0.tag.length).toBeGreaterThan(0)
    })

    test('throws when Mac0 has embedded payload and detachedPayload is also passed to authenticate()', async () => {
      const mac0 = Mac0.create({ payload })
      await expect(mac0.authenticate({ key: macKey, detachedPayload }, mac0Context)).rejects.toThrow(
        'Cannot provide detachedPayload when the Mac0 already contains an embedded payload'
      )
    })

    test('throws when payload is null and no detachedPayload is passed to authenticate()', async () => {
      const mac0 = Mac0.create({ payload: null })
      await expect(mac0.authenticate({ key: macKey }, mac0Context)).rejects.toThrow()
    })
  })
})
