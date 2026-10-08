import { describe, expect, test } from 'vitest'
import { SDJwtException } from '../../utils/error'

describe('Error tests', () => {
  test('Detail', () => {
    try {
      throw new SDJwtException('msg', { details: { info: 'details' } })
    } catch (e: unknown) {
      const exception = e as SDJwtException
      expect(exception.getFullMessage()).toEqual('SDJwtException: msg - {"info":"details"}')
    }
  })
  test('Code and cause', () => {
    const cause = new Error('underlying')
    const exception = new SDJwtException('msg', { code: 'JWT_EXPIRED', cause })

    expect(exception.code).toBe('JWT_EXPIRED')
    expect(exception.cause).toBe(cause)
    expect(exception.details).toBeUndefined()
    expect(exception.getFullMessage()).toEqual('SDJwtException: msg ')
  })
})
