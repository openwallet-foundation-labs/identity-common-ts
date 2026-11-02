import { IdentityError } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { CborDecodeError, CborError } from '../cbor/error'
import { CoseError, CoseInvalidSignatureError, CwtClaimVerificationError } from '../cose/error'
import * as cose from '../index'

type ErrorClass = new (message?: string, options?: { cause?: unknown; details?: unknown }) => Error

// Every error class the package exports, so that one added later is covered without listing it here
const errorClasses = (Object.entries(cose) as Array<[string, unknown]>).filter(
  (entry): entry is [string, ErrorClass] =>
    typeof entry[1] === 'function' &&
    (entry[1] === CoseError ||
      entry[1] === CborError ||
      entry[1].prototype instanceof CoseError ||
      entry[1].prototype instanceof CborError)
)

describe('cose errors', () => {
  it('can be caught as its own class, as CoseError and as an IdentityError', () => {
    const error = new CoseInvalidSignatureError()

    expect(error).toBeInstanceOf(CoseInvalidSignatureError)
    expect(error).toBeInstanceOf(CoseError)
    expect(error).toBeInstanceOf(IdentityError)
    expect(error).toBeInstanceOf(Error)
  })

  it('is named after the class it is, and defaults its message to that name', () => {
    expect(new CwtClaimVerificationError().name).toBe('CwtClaimVerificationError')
    expect(new CwtClaimVerificationError().message).toBe('CwtClaimVerificationError')
    expect(new CwtClaimVerificationError('the token expired').message).toBe('the token expired')
  })

  it('keeps the cause', () => {
    const cause = new Error('the actual failure')

    expect(new CoseInvalidSignatureError('wrapped', { cause }).cause).toBe(cause)
  })

  it('applies the same to a cbor error', () => {
    const error = new CborDecodeError('unable to decode')

    expect(error).toBeInstanceOf(CborDecodeError)
    expect(error).toBeInstanceOf(IdentityError)
    expect(error.name).toBe('CborDecodeError')
  })

  it('finds the error classes of both cose and cbor among the exports', () => {
    expect(errorClasses.map(([name]) => name)).toEqual(
      expect.arrayContaining([
        'CoseError',
        'CborError',
        'CborDecodeError',
        'CborEncodeError',
        'CwtClaimVerificationError',
      ])
    )
  })

  it.each(errorClasses)('names %s after its class', (name, ErrorClass) => {
    expect(new ErrorClass().name).toBe(name)
  })

  it.each(errorClasses)('makes %s an IdentityError', (_, ErrorClass) => {
    expect(new ErrorClass()).toBeInstanceOf(IdentityError)
  })

  it.each([
    ['a cose error', CwtClaimVerificationError],
    ['a cbor error', CborDecodeError],
  ])('keeps the details given to %s', (_, ErrorClass) => {
    expect(new ErrorClass('the token expired', { details: { claim: 'exp' } }).details).toEqual({ claim: 'exp' })
  })

  it('has no details unless it is given some', () => {
    expect(new CwtClaimVerificationError('the token expired').details).toBeUndefined()
  })

  it('reports its name, message and details in the full message', () => {
    expect(new CwtClaimVerificationError('the token expired', { details: { claim: 'exp' } }).getFullMessage()).toBe(
      'CwtClaimVerificationError: the token expired - {"claim":"exp"}'
    )
  })
})
