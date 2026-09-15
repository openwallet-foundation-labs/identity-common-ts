import { describe, expect, it } from 'vitest'
import { IdentityCommonException } from '../identity-common-exception'
import { IdentityException } from '../identity-exception'

/**
 * `IdentityException` sets the prototype from `new.target`, so that `instanceof` holds for every
 * subclass however deep. Setting a fixed prototype instead would overwrite the one `super()`
 * installed, and every subclass would have to set it again to repair that — which is what these
 * tests are here to keep from creeping back in.
 */
describe('IdentityException', () => {
  class Custom extends IdentityException {
    constructor(message: string) {
      super(message)
      this.name = 'Custom'
    }
  }

  class NestedCustom extends Custom {}
  class NestedCommon extends IdentityCommonException {}

  it('can be caught as itself and as an Error', () => {
    const exception = new IdentityException('something is off')

    expect(exception).toBeInstanceOf(IdentityException)
    expect(exception).toBeInstanceOf(Error)
  })

  it('can be caught as a subclass that does not set its own prototype', () => {
    const exception = new Custom('something is off')

    expect(exception).toBeInstanceOf(Custom)
    expect(exception).toBeInstanceOf(IdentityException)
    expect(exception).toBeInstanceOf(Error)
  })

  it('can be caught as a subclass of a subclass', () => {
    expect(new NestedCustom('something is off')).toBeInstanceOf(NestedCustom)
    expect(new NestedCustom('something is off')).toBeInstanceOf(Custom)

    expect(new NestedCommon('something is off')).toBeInstanceOf(NestedCommon)
    expect(new NestedCommon('something is off')).toBeInstanceOf(IdentityCommonException)
    expect(new NestedCommon('something is off')).toBeInstanceOf(IdentityException)
  })

  it('is named after the class it is', () => {
    expect(new IdentityException('x').name).toBe('IdentityException')
    expect(new IdentityCommonException('x').name).toBe('IdentityCommonException')
    expect(new Custom('x').name).toBe('Custom')
  })

  it('keeps the details and reports them in the full message', () => {
    const exception = new IdentityCommonException('something is off', { claim: 'iss' })

    expect(exception.details).toEqual({ claim: 'iss' })
    expect(exception.getFullMessage()).toBe('IdentityCommonException: something is off - {"claim":"iss"}')
  })
})
