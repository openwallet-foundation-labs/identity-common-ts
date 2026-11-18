import { describe, expect, test } from 'vitest'
import { JoseNotSupportedError } from '../error'
import {
  type CoseAlgorithmIdentifier,
  coseAlgorithmsToJwaSignatureAlgorithms,
  coseAlgorithmToJwaSignatureAlgorithm,
  jwaSignatureAlgorithmsToCoseAlgorithms,
  jwaSignatureAlgorithmToCoseAlgorithm,
} from '../jwa/cose-algorithm'

describe('algorithm-transform', () => {
  describe('jwaSignatureAlgorithmToCoseAlgorithm', () => {
    test('should transform EdDSA algorithms', () => {
      expect(jwaSignatureAlgorithmToCoseAlgorithm('Ed25519')).toBe(-19)
      expect(jwaSignatureAlgorithmToCoseAlgorithm('Ed448')).toBe(-53)
    })

    test('should transform deprecated polymorphic EdDSA algorithm', () => {
      // EdDSA is deprecated in JWA (RFC 9864 Section 4.1.2)
      // Maps to Ed25519 as it's the most common use case
      expect(jwaSignatureAlgorithmToCoseAlgorithm('EdDSA')).toBe(-19)
    })

    test('should transform ECDSA algorithms', () => {
      expect(jwaSignatureAlgorithmToCoseAlgorithm('ES256')).toBe(-9)
      expect(jwaSignatureAlgorithmToCoseAlgorithm('ES384')).toBe(-51)
      expect(jwaSignatureAlgorithmToCoseAlgorithm('ES512')).toBe(-52)
      expect(jwaSignatureAlgorithmToCoseAlgorithm('ES256K')).toBe(-47)
    })

    test('should transform RSA algorithms', () => {
      expect(jwaSignatureAlgorithmToCoseAlgorithm('RS256')).toBe(-257)
      expect(jwaSignatureAlgorithmToCoseAlgorithm('RS384')).toBe(-258)
      expect(jwaSignatureAlgorithmToCoseAlgorithm('RS512')).toBe(-259)
      expect(jwaSignatureAlgorithmToCoseAlgorithm('PS256')).toBe(-37)
      expect(jwaSignatureAlgorithmToCoseAlgorithm('PS384')).toBe(-38)
      expect(jwaSignatureAlgorithmToCoseAlgorithm('PS512')).toBe(-39)
    })

    test('should return undefined for unknown algorithms', () => {
      expect(jwaSignatureAlgorithmToCoseAlgorithm('UnknownAlg')).toBeUndefined()
    })

    test('should transform HMAC algorithms', () => {
      expect(jwaSignatureAlgorithmToCoseAlgorithm('HS256')).toBe(5)
      expect(jwaSignatureAlgorithmToCoseAlgorithm('HS384')).toBe(6)
      expect(jwaSignatureAlgorithmToCoseAlgorithm('HS512')).toBe(7)
    })
  })

  describe('coseAlgorithmToJwaSignatureAlgorithm', () => {
    test('should transform EdDSA algorithms', () => {
      expect(coseAlgorithmToJwaSignatureAlgorithm(-19)).toBe('Ed25519')
      expect(coseAlgorithmToJwaSignatureAlgorithm(-53)).toBe('Ed448')
    })

    test('should transform ECDSA algorithms', () => {
      expect(coseAlgorithmToJwaSignatureAlgorithm(-9)).toBe('ES256')
      expect(coseAlgorithmToJwaSignatureAlgorithm(-51)).toBe('ES384')
      expect(coseAlgorithmToJwaSignatureAlgorithm(-52)).toBe('ES512')
      expect(coseAlgorithmToJwaSignatureAlgorithm(-47)).toBe('ES256K')
    })

    test('should transform deprecated polymorphic ECDSA algorithms', () => {
      expect(coseAlgorithmToJwaSignatureAlgorithm(-7)).toBe('ES256')
      expect(coseAlgorithmToJwaSignatureAlgorithm(-35)).toBe('ES384')
      expect(coseAlgorithmToJwaSignatureAlgorithm(-36)).toBe('ES512')
    })

    test('should transform deprecated polymorphic EdDSA algorithm', () => {
      expect(coseAlgorithmToJwaSignatureAlgorithm(-8)).toBe('Ed25519')
    })

    test('should transform RSA algorithms', () => {
      expect(coseAlgorithmToJwaSignatureAlgorithm(-257)).toBe('RS256')
      expect(coseAlgorithmToJwaSignatureAlgorithm(-258)).toBe('RS384')
      expect(coseAlgorithmToJwaSignatureAlgorithm(-259)).toBe('RS512')
      expect(coseAlgorithmToJwaSignatureAlgorithm(-37)).toBe('PS256')
      expect(coseAlgorithmToJwaSignatureAlgorithm(-38)).toBe('PS384')
      expect(coseAlgorithmToJwaSignatureAlgorithm(-39)).toBe('PS512')
    })

    test('should return undefined for unknown algorithms', () => {
      expect(coseAlgorithmToJwaSignatureAlgorithm(999)).toBeUndefined()
      expect(coseAlgorithmToJwaSignatureAlgorithm(0)).toBeUndefined()
    })

    test('should transform HMAC algorithms', () => {
      expect(coseAlgorithmsToJwaSignatureAlgorithms([5, 6, 7])).toEqual(['HS256', 'HS384', 'HS512'])
    })
  })

  describe('jwaSignatureAlgorithmsToCoseAlgorithms', () => {
    test('should transform array of JWA algorithms to COSE', () => {
      const jwaAlgs = ['Ed25519', 'ES256', 'ES384']
      const coseAlgs = jwaSignatureAlgorithmsToCoseAlgorithms(jwaAlgs)
      expect(coseAlgs).toEqual([-19, -9, -51])
    })

    test('should filter out unknown algorithms', () => {
      const jwaAlgs = ['Ed25519', 'UnknownAlg', 'ES256']
      const coseAlgs = jwaSignatureAlgorithmsToCoseAlgorithms(jwaAlgs)
      expect(coseAlgs).toEqual([-19, -9])
    })

    test('should throw error for unknown algorithms if enabled', () => {
      const jwaAlgs = ['Ed25519', 'UnknownAlg', 'ES256']
      expect(() => jwaSignatureAlgorithmsToCoseAlgorithms(jwaAlgs, true)).toThrow(JoseNotSupportedError)
    })

    test('should handle empty array', () => {
      expect(jwaSignatureAlgorithmsToCoseAlgorithms([])).toEqual([])
    })

    test('should handle array with all unknown algorithms', () => {
      const jwaAlgs = ['Unknown1', 'Unknown2']
      const coseAlgs = jwaSignatureAlgorithmsToCoseAlgorithms(jwaAlgs)
      expect(coseAlgs).toEqual([])
    })
  })

  describe('coseAlgorithmsToJwaSignatureAlgorithms', () => {
    test('should transform array of COSE algorithms to JWA', () => {
      const coseAlgs = [-19, -9, -51]
      const jwaAlgs = coseAlgorithmsToJwaSignatureAlgorithms(coseAlgs)
      expect(jwaAlgs).toEqual(['Ed25519', 'ES256', 'ES384'])
    })

    test('should transform deprecated COSE algorithms', () => {
      const coseAlgs = [-7, -8, -9]
      const jwaAlgs = coseAlgorithmsToJwaSignatureAlgorithms(coseAlgs)
      expect(jwaAlgs).toEqual(['ES256', 'Ed25519', 'ES256'])
    })

    test('should filter out unknown algorithms', () => {
      const coseAlgs = [-19, 999, -9]
      const jwaAlgs = coseAlgorithmsToJwaSignatureAlgorithms(coseAlgs)
      expect(jwaAlgs).toEqual(['Ed25519', 'ES256'])
    })

    test('should throw error for unknown algorithms if enabled', () => {
      const coseAlgs = [-19, 999, -9]
      expect(() => coseAlgorithmsToJwaSignatureAlgorithms(coseAlgs, true)).toThrow(JoseNotSupportedError)
    })

    test('should handle empty array', () => {
      expect(coseAlgorithmsToJwaSignatureAlgorithms([])).toEqual([])
    })

    test('should handle array with all unknown algorithms', () => {
      const coseAlgs = [999, 1000]
      const jwaAlgs = coseAlgorithmsToJwaSignatureAlgorithms(coseAlgs)
      expect(jwaAlgs).toEqual([])
    })
  })

  describe('round-trip transformations', () => {
    test('JWA -> COSE -> JWA should preserve algorithm', () => {
      const jwaAlg = 'Ed25519'
      const coseAlg = jwaSignatureAlgorithmToCoseAlgorithm(jwaAlg)
      const backToJwa = coseAlgorithmToJwaSignatureAlgorithm(coseAlg as CoseAlgorithmIdentifier)
      expect(backToJwa).toBe(jwaAlg)
    })

    test('should handle ES256 round-trip', () => {
      const jwaAlg = 'ES256'
      const coseAlg = jwaSignatureAlgorithmToCoseAlgorithm(jwaAlg)
      expect(coseAlg).toBe(-9) // ESP256
      const backToJwa = coseAlgorithmToJwaSignatureAlgorithm(coseAlg as CoseAlgorithmIdentifier)
      expect(backToJwa).toBe(jwaAlg)
    })

    test('should handle array round-trip', () => {
      const jwaAlgs = ['Ed25519', 'ES256', 'ES384']
      const coseAlgs = jwaSignatureAlgorithmsToCoseAlgorithms(jwaAlgs)
      const backToJwa = coseAlgorithmsToJwaSignatureAlgorithms(coseAlgs)
      expect(backToJwa).toEqual(jwaAlgs)
    })
  })

  describe('RFC 9864 compliance', () => {
    test('should map EdDSA according to RFC 9864 Table 2', () => {
      // From RFC 9864 Section 2.2, Table 2
      expect(jwaSignatureAlgorithmToCoseAlgorithm('Ed25519')).toBe(-19)
      expect(jwaSignatureAlgorithmToCoseAlgorithm('Ed448')).toBe(-53)
    })

    test('should map ECDSA according to RFC 9864 Table 1', () => {
      // From RFC 9864 Section 2.1, Table 1
      // Note: JWA uses ES256/ES384/ES512 which map to COSE ESP256/ESP384/ESP512
      expect(jwaSignatureAlgorithmToCoseAlgorithm('ES256')).toBe(-9) // ESP256
      expect(jwaSignatureAlgorithmToCoseAlgorithm('ES384')).toBe(-51) // ESP384
      expect(jwaSignatureAlgorithmToCoseAlgorithm('ES512')).toBe(-52) // ESP512
    })
  })
})
