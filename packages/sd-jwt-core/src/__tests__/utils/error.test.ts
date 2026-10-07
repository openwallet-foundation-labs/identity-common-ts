import { describe, expect, test } from 'vitest'
import { SDJWTException } from '../../utils/error'

describe('Error tests', () => {
  test('Detail', () => {
    try {
      throw new SDJWTException('msg', { details: { info: 'details' } })
    } catch (e: unknown) {
      const exception = e as SDJWTException
      expect(exception.getFullMessage()).toEqual('SDJWTException: msg - {"info":"details"}')
    }
  })
  test('Code and cause', () => {
    const cause = new Error('underlying')
    const exception = new SDJWTException('msg', { code: 'JWT_EXPIRED', cause })

    expect(exception.code).toBe('JWT_EXPIRED')
    expect(exception.cause).toBe(cause)
    expect(exception.details).toBeUndefined()
    expect(exception.getFullMessage()).toEqual('SDJWTException: msg ')
  })
})
