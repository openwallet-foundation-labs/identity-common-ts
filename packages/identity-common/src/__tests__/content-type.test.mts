import { describe, expect, it } from 'vitest'
import { createAcceptHeader, extractMediaType, isMediaType } from '../../src'

describe('content type', () => {
  describe('extractMediaType', () => {
    it('should return the media type as is when there are no parameters', () => {
      expect(extractMediaType('application/statuslist+jwt')).toStrictEqual('application/statuslist+jwt')
    })

    it('should strip parameters and surrounding whitespace', () => {
      expect(extractMediaType(' application/statuslist+jwt ; charset=utf-8 ')).toStrictEqual(
        'application/statuslist+jwt'
      )
    })

    it('should lowercase the media type', () => {
      expect(extractMediaType('Application/StatusList+JWT')).toStrictEqual('application/statuslist+jwt')
    })

    it('should return undefined for missing or empty values', () => {
      expect(extractMediaType(undefined)).toBeUndefined()
      expect(extractMediaType(null)).toBeUndefined()
      expect(extractMediaType('')).toBeUndefined()
      expect(extractMediaType('  ')).toBeUndefined()
      expect(extractMediaType('; charset=utf-8')).toBeUndefined()
    })
  })

  describe('isMediaType', () => {
    it('should match ignoring casing and parameters', () => {
      expect(isMediaType('Application/StatusList+JWT; charset=UTF-8', 'application/statuslist+jwt')).toBe(true)
    })

    it('should match against a list of expected media types', () => {
      expect(
        isMediaType('application/statuslist+cwt', ['application/statuslist+jwt', 'application/statuslist+cwt'])
      ).toBe(true)
    })

    it('should not match a different media type', () => {
      expect(isMediaType('application/statuslist+cwt', 'application/statuslist+jwt')).toBe(false)
      expect(isMediaType('application/json', ['application/statuslist+jwt', 'application/statuslist+cwt'])).toBe(false)
    })

    it('should not match a media type that is only a prefix', () => {
      expect(isMediaType('application/statuslist+jwt2', 'application/statuslist+jwt')).toBe(false)
    })

    it('should return false for missing or empty values', () => {
      expect(isMediaType(undefined, 'application/statuslist+jwt')).toBe(false)
      expect(isMediaType(null, 'application/statuslist+jwt')).toBe(false)
      expect(isMediaType('', 'application/statuslist+jwt')).toBe(false)
      expect(isMediaType('application/statuslist+jwt', [])).toBe(false)
    })
  })

  describe('createAcceptHeader', () => {
    it('should ask for a single media type without a quality value', () => {
      expect(createAcceptHeader(['application/json'])).toStrictEqual('application/json')
    })

    it('should give every media type after the first a lower quality value', () => {
      expect(createAcceptHeader(['application/jwt', 'application/jwk-set+json', 'application/json'])).toStrictEqual(
        'application/jwt, application/jwk-set+json;q=0.9, application/json;q=0.8'
      )
    })

    it('should never go below q=0.1, which keeps every media type acceptable', () => {
      const mediaTypes = Array.from({ length: 12 }, (_, index) => `application/type-${index}`)

      expect(createAcceptHeader(mediaTypes).split(', ').slice(-3)).toStrictEqual([
        'application/type-9;q=0.1',
        'application/type-10;q=0.1',
        'application/type-11;q=0.1',
      ])
    })

    it('should drop duplicates', () => {
      expect(createAcceptHeader(['application/cwt', 'application/cwt', 'application/jwt'])).toStrictEqual(
        'application/cwt, application/jwt;q=0.9'
      )
    })
  })
})
