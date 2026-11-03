import { IdentityError } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import {
  parseTrustedList,
  TrustedListError,
  TrustedListParseError,
  TrustedListSignatureError,
  verifyTrustedListSignature,
} from '../index'
import { UNSIGNED_TSL_XML } from './fixtures.mjs'

describe('trusted list errors', () => {
  it('rejects a document that is not a trusted list with a parse error that is an IdentityError', () => {
    const parse = () => parseTrustedList('<root/>')

    expect(parse).toThrow(TrustedListParseError)
    expect(parse).toThrow(IdentityError)
  })

  it('rejects an unsigned trusted list with a signature error that is an IdentityError', async () => {
    await expect(verifyTrustedListSignature(UNSIGNED_TSL_XML)).rejects.toSatisfy(
      (error) => error instanceof TrustedListSignatureError && error instanceof IdentityError
    )
  })

  it.each([
    ['TrustedListError', TrustedListError],
    ['TrustedListParseError', TrustedListParseError],
    ['TrustedListSignatureError', TrustedListSignatureError],
  ])('names %s after its class', (name, ErrorClass) => {
    expect(new ErrorClass('the list is off').name).toBe(name)
  })

  it.each([
    ['TrustedListParseError', TrustedListParseError],
    ['TrustedListSignatureError', TrustedListSignatureError],
  ])('makes %s a TrustedListError', (_, ErrorClass) => {
    expect(new ErrorClass('the list is off')).toBeInstanceOf(TrustedListError)
  })

  it('names a subclass that does not set a name after that subclass', () => {
    class TrustedListExpiredError extends TrustedListError {}

    expect(new TrustedListExpiredError('the list expired').name).toBe('TrustedListExpiredError')
  })

  it('keeps the cause', () => {
    const cause = new Error('xmldsig failure')

    expect(new TrustedListSignatureError('the signature could not be verified', { cause }).cause).toBe(cause)
  })
})
