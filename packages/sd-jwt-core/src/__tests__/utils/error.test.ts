import { describe, expect, test } from 'vitest'
import { SDJWTError } from '../../utils/error'

describe('Error tests', () => {
  test('Detail', () => {
    try {
      throw new SDJWTError('msg', { details: { info: 'details' } })
    } catch (e: unknown) {
      const exception = e as SDJWTError
      expect(exception.getFullMessage()).toEqual('SDJWTError: msg - {"info":"details"}')
    }
  })
  test('Code and cause', () => {
    const cause = new Error('underlying')
    const exception = new SDJWTError('msg', { code: 'JWT_EXPIRED', cause })

    expect(exception.code).toBe('JWT_EXPIRED')
    expect(exception.cause).toBe(cause)
    expect(exception.details).toBeUndefined()
    expect(exception.getFullMessage()).toEqual('SDJWTError: msg ')
  })
})
