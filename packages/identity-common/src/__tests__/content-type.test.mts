import { describe, expect, it } from 'vitest'
import { extractMediaType, isMediaType } from '../../src'

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
})
