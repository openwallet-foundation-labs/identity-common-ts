import { IdentityException } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { CborDecodeError } from '../cbor/error'
import { CoseError, CoseInvalidSignatureError, CwtClaimVerificationError } from '../cose/error'

describe('cose errors', () => {
  it('can be caught as its own class, as CoseError and as an IdentityException', () => {
    const error = new CoseInvalidSignatureError()

    expect(error).toBeInstanceOf(CoseInvalidSignatureError)
    expect(error).toBeInstanceOf(CoseError)
    expect(error).toBeInstanceOf(IdentityException)
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
    expect(error).toBeInstanceOf(IdentityException)
    expect(error.name).toBe('CborDecodeError')
  })
})
