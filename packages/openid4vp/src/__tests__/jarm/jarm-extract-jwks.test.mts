import type { Jwk } from '@owf/jose'
import { describe, expect, test } from 'vitest'
import { extractEncryptionJwkFromJwks } from '../../jarm/jarm-extract-jwks.js'

const key = (kid: string, use?: 'sig' | 'enc'): Jwk => ({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', kid, use })

// RFC 7517 Section 4.2: a key with `use: 'sig'` is meant for signatures, not for encryption
describe('extractEncryptionJwkFromJwks', () => {
  test('does not pick a signing key, also when it is the only key', () => {
    expect(extractEncryptionJwkFromJwks({ keys: [key('sig', 'sig')] }, {})).toBeUndefined()
  })

  test('picks a signing key when the kid names it', () => {
    expect(extractEncryptionJwkFromJwks({ keys: [key('sig', 'sig')] }, { kid: 'sig' })).toEqual(key('sig', 'sig'))
  })

  test('prefers a key with use enc over one without a use', () => {
    const jwks = { keys: [key('sig', 'sig'), key('unstated'), key('enc', 'enc')] }

    expect(extractEncryptionJwkFromJwks(jwks, {})).toEqual(key('enc', 'enc'))
  })
})
