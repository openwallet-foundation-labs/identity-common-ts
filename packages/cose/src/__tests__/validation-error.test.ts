// Imported for its side effects too: the package is loaded the way an application loads it
import '../index'

import { ValidationError } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import z from 'zod'
import { cborEncode } from '../cbor'
import { CoseValidationError, CwtPayload, type CwtPayloadDecodedStructure, RegisteredCwtClaimKey } from '../cose'
import { TypedMap } from '../utils/typed-map'

const invalidClaims = () => cborEncode(new Map<number, unknown>([[RegisteredCwtClaimKey.ExpirationTime, 'tomorrow']]))

describe('a cose structure that does not match its schema', () => {
  it('is rejected with a CoseValidationError, a ValidationError of @owf/identity-common', () => {
    expect(() => CwtPayload.decode(invalidClaims())).toThrow(CoseValidationError)
    expect(() => CwtPayload.decode(invalidClaims())).toThrow(ValidationError)
  })

  it('is rejected with the issues, each at the claim it is about', () => {
    expect(() => CwtPayload.decode(invalidClaims())).toThrow(
      expect.objectContaining({
        message: 'Error decoding CwtPayload\n  - ExpirationTime (4): expected number, received string (invalid_type)',
        issues: [
          {
            severity: 'error',
            code: 'invalid_type',
            path: [4],
            pathLabels: ['ExpirationTime (4)'],
            message: 'expected number, received string',
            context: { expected: 'number' },
          },
        ],
      })
    )
  })
})

describe('a cose structure that cannot be encoded', () => {
  // The constructor takes the claims as they are, so only encoding checks them
  const unencodable = () =>
    new CwtPayload(
      TypedMap.fromMap(
        new Map<number, unknown>([[RegisteredCwtClaimKey.ExpirationTime, 'tomorrow']])
      ) as unknown as CwtPayloadDecodedStructure
    )

  it('is rejected with the ValidationError of @owf/identity-common', () => {
    expect(() => unencodable().encode()).toThrow(ValidationError)
  })

  it('is rejected with the issues, each at the claim it is about', () => {
    expect(() => unencodable().encode()).toThrow(
      'Error encoding CwtPayload\n  - ExpirationTime (4): expected number, received string'
    )
  })
})

describe('importing @owf/cose', () => {
  it('leaves the messages zod gives for the schemas of an application unchanged', () => {
    expect(z.string().safeParse(1).error?.issues[0].message).toBe('Invalid input: expected string, received number')
  })
})
