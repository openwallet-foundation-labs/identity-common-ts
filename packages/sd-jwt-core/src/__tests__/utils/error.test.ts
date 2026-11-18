import { describe, expect, test } from 'vitest'
import { SdJwtError } from '../../utils/error'

describe('Error tests', () => {
  test('Detail', () => {
    try {
      throw new SdJwtError('msg', { details: { info: 'details' } })
    } catch (e: unknown) {
      const exception = e as SdJwtError
      expect(exception.getFullMessage()).toEqual('SdJwtError: msg - {"info":"details"}')
    }
  })
  test('Code and cause', () => {
    const cause = new Error('underlying')
    const exception = new SdJwtError('msg', { code: 'JWT_EXPIRED', cause })

    expect(exception.code).toBe('JWT_EXPIRED')
    expect(exception.cause).toBe(cause)
    expect(exception.details).toBeUndefined()
    expect(exception.getFullMessage()).toEqual('SdJwtError: msg ')
  })
})
