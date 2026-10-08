import { IdentityError } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import {
  JoseClaimVerificationError,
  JoseError,
  JoseInvalidArgumentError,
  JoseParseError,
  JoseVerificationError,
} from '../error'

describe('errors', () => {
  it('can be caught as a JoseError and as an IdentityError', () => {
    const error = new JoseParseError('something is off')

    expect(error).toBeInstanceOf(JoseParseError)
    expect(error).toBeInstanceOf(JoseError)
    expect(error).toBeInstanceOf(IdentityError)
    expect(error).toBeInstanceOf(Error)
  })

  it('is named after the class it is', () => {
    expect(new JoseClaimVerificationError('expired').name).toBe('JoseClaimVerificationError')
  })

  it('keeps the cause', () => {
    const cause = new Error('the actual failure')

    expect(new JoseParseError('wrapped', { cause }).cause).toBe(cause)
  })

  // A mistake in the calling code says nothing about the token, so a caller that maps token errors
  // onto responses must not mistake it for one
  it('reports an invalid argument as neither a malformed nor an unverified token', () => {
    const error = new JoseInvalidArgumentError('skewSeconds must be a number')

    expect(error).toBeInstanceOf(JoseError)
    expect(error).not.toBeInstanceOf(JoseParseError)
    expect(error).not.toBeInstanceOf(JoseVerificationError)
  })

  it('names an invalid argument error after its class', () => {
    expect(new JoseInvalidArgumentError('skewSeconds must be a number').name).toBe('JoseInvalidArgumentError')
  })
})
