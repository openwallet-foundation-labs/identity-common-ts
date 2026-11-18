import { IdentityError, ValidationError } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import {
  JoseError,
  JoseInvalidArgumentError,
  JoseParseError,
  JoseValidationError,
  type JoseValidationIssue,
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
    expect(new JoseValidationError('expired', []).name).toBe('JoseValidationError')
  })

  it('reports a validation error as a ValidationError of @owf/identity-common, with its issues', () => {
    const issue: JoseValidationIssue = {
      severity: 'error',
      code: 'invalid_typ',
      path: ['typ'],
      message: 'typ must be kb+jwt',
      context: { expected: ['kb+jwt'], actual: 'JWT' },
    }
    const error = new JoseValidationError('Invalid JWS protected header', [issue])

    expect(error).toBeInstanceOf(ValidationError)
    expect(error).toBeInstanceOf(IdentityError)
    expect(error).not.toBeInstanceOf(JoseError)
    expect(error.issues).toEqual([issue])
    expect(error.message).toBe('Invalid JWS protected header\n  - typ: typ must be kb+jwt (invalid_typ)')
  })

  it('finds the issue of a claim that does not verify by its code, typed by the code', () => {
    const expiredAt = new Date(0)
    const error = new JoseValidationError('The token is expired', [
      { severity: 'error', code: 'invalid_typ', path: ['typ'], message: 'typ', context: { expected: [], actual: 1 } },
      { severity: 'error', code: 'expired', path: ['exp'], message: 'expired', context: { expiredAt } },
    ])

    expect(error).not.toBeInstanceOf(JoseVerificationError)
    expect(error.findIssue('expired')?.context.expiredAt).toBe(expiredAt)
    expect(error.findIssue('claim_value_mismatch')).toBeUndefined()
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
