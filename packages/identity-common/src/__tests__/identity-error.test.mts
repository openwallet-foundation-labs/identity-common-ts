import { describe, expect, it } from 'vitest'
import { IdentityCommonError } from '../identity-common-error'
import { IdentityError } from '../identity-error'

/**
 * `IdentityError` sets the prototype from `new.target`, so that `instanceof` holds for every
 * subclass however deep. Setting a fixed prototype instead would overwrite the one `super()`
 * installed, and every subclass would have to set it again to repair that — which is what these
 * tests are here to keep from creeping back in.
 */
describe('IdentityError', () => {
  class Custom extends IdentityError {
    constructor(message: string) {
      super(message)
      this.name = 'Custom'
    }
  }

  class NestedCustom extends Custom {}
  class NestedCommon extends IdentityCommonError {}

  // Subclasses that leave the name to `IdentityError`, as most error classes in the repository do
  class Unnamed extends IdentityError {}
  class NestedUnnamed extends Unnamed {}

  it('can be caught as itself and as an Error', () => {
    const error = new IdentityError('something is off')

    expect(error).toBeInstanceOf(IdentityError)
    expect(error).toBeInstanceOf(Error)
  })

  it('can be caught as a subclass that does not set its own prototype', () => {
    const error = new Custom('something is off')

    expect(error).toBeInstanceOf(Custom)
    expect(error).toBeInstanceOf(IdentityError)
    expect(error).toBeInstanceOf(Error)
  })

  it('can be caught as a subclass of a subclass', () => {
    expect(new NestedCustom('something is off')).toBeInstanceOf(NestedCustom)
    expect(new NestedCustom('something is off')).toBeInstanceOf(Custom)

    expect(new NestedCommon('something is off')).toBeInstanceOf(NestedCommon)
    expect(new NestedCommon('something is off')).toBeInstanceOf(IdentityCommonError)
    expect(new NestedCommon('something is off')).toBeInstanceOf(IdentityError)
  })

  it('is named after the class it is', () => {
    expect(new IdentityError('x').name).toBe('IdentityError')
    expect(new IdentityCommonError('x').name).toBe('IdentityCommonError')
    expect(new Custom('x').name).toBe('Custom')
  })

  it('names a subclass that does not set a name after that subclass', () => {
    expect(new Unnamed('x').name).toBe('Unnamed')
  })

  it('names a subclass of such a subclass after the class that was constructed', () => {
    expect(new NestedUnnamed('x').name).toBe('NestedUnnamed')
  })

  it('keeps the name a class sets itself for a subclass of it that sets none', () => {
    expect(new NestedCustom('x').name).toBe('Custom')
    expect(new NestedCommon('x').name).toBe('IdentityCommonError')
  })

  it('reports the name of a subclass that does not set one in the full message', () => {
    expect(new Unnamed('something is off', { claim: 'iss' }).getFullMessage()).toBe(
      'Unnamed: something is off - {"claim":"iss"}'
    )
  })

  it('keeps the details and reports them in the full message', () => {
    const error = new IdentityCommonError('something is off', { claim: 'iss' })

    expect(error.details).toEqual({ claim: 'iss' })
    expect(error.getFullMessage()).toBe('IdentityCommonError: something is off - {"claim":"iss"}')
  })
})
