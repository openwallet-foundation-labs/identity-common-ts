import { dateToSeconds, parseWithSchema } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import type z from 'zod'
import { JoseValidationError } from '../error'
import { zCompactJwe, zJweHeader } from '../jwe/z-jwe'
import { zCompactJws } from '../jws/z-jws'
import { verifyJwtClaims } from '../jwt/verify-jwt-claims'
import { zCompactJwt, zJwtPayload } from '../jwt/z-jwt'

const now = new Date('2026-09-15T12:00:00Z')

const errorOf = (run: () => unknown) => {
  try {
    run()
  } catch (error) {
    return error
  }
}

const codesOf = (schema: z.ZodType, value: unknown) => {
  const result = parseWithSchema(schema, value)
  return result.success ? [] : result.issues.map(({ code, path, context }) => ({ code, path, context }))
}

describe('claims that do not verify', () => {
  it('throws one JoseValidationError with an issue for every claim', () => {
    const exp = dateToSeconds(now) - 3600
    const nbf = dateToSeconds(now) + 3600
    const error = errorOf(() =>
      verifyJwtClaims(
        { iss: 'https://other.example', exp, nbf, aud: ['https://a.example'] },
        { now, expectedIssuer: 'https://issuer.example', expectedAudience: 'https://b.example', expectedNonce: 'n-1' }
      )
    )

    expect(error).toBeInstanceOf(JoseValidationError)
    expect((error as JoseValidationError).issues).toMatchObject([
      {
        code: 'claim_value_mismatch',
        path: ['iss'],
        context: { expected: ['https://issuer.example'], actual: 'https://other.example' },
      },
      { code: 'claim_missing', path: ['nonce'] },
      {
        code: 'claim_value_mismatch',
        path: ['aud'],
        context: { expected: ['https://b.example'], actual: ['https://a.example'] },
      },
      { code: 'expired', path: ['exp'], context: { expiredAt: new Date(exp * 1000) } },
      { code: 'not_yet_valid', path: ['nbf'], context: { validFrom: new Date(nbf * 1000) } },
    ])
  })

  it('reports a claim that is required and expected as missing once', () => {
    const error = errorOf(() =>
      verifyJwtClaims({}, { now, requiredClaims: ['iat'], maxAgeSeconds: 60, expectedIssuer: 'https://issuer.example' })
    )

    expect((error as JoseValidationError).issues.map(({ code, path }) => ({ code, path }))).toEqual([
      { code: 'claim_missing', path: ['iat'] },
      { code: 'claim_missing', path: ['iss'] },
    ])
  })

  it('reports a time claim that is not a NumericDate once', () => {
    const error = errorOf(() => verifyJwtClaims({ iat: Number.NaN }, { now, maxAgeSeconds: 60 }))

    expect((error as JoseValidationError).issues).toMatchObject([
      { code: 'invalid_type', path: ['iat'], context: { expected: 'number' } },
    ])
  })

  it('reports an iat older than the maximum age as expired at the end of that age', () => {
    const iat = dateToSeconds(now) - 3600
    const error = errorOf(() => verifyJwtClaims({ iat }, { now, skewSeconds: 0, maxAgeSeconds: 60 }))

    expect((error as JoseValidationError).findIssue('expired')?.context.expiredAt).toEqual(new Date((iat + 60) * 1000))
  })
})

describe('the compact serializations', () => {
  const invalidFormat = (format: string) => [{ code: 'invalid_format', path: [], context: { format } }]

  it('reports a JWT without a payload as invalid_format, which a detached JWS may be', () => {
    expect(codesOf(zCompactJwt, 'eyJh..c2ln')).toEqual(invalidFormat('jwt'))
    expect(codesOf(zCompactJws, 'eyJh..c2ln')).toEqual([])
  })

  it('accepts a JWE with an empty encrypted key', () => {
    expect(codesOf(zCompactJwe, 'eyJh..aXY.Y3Q.dGFn')).toEqual([])
  })

  it.each([
    ['four parts', 'eyJh..aXY.Y3Q'],
    ['an empty authentication tag', 'eyJh..aXY.Y3Q.'],
    ['an empty ciphertext', 'eyJh..aXY..dGFn'],
    ['a part that is not base64url', 'eyJh..aXY.Y3Q=.dGFn'],
  ])('reports a JWE with %s as invalid_format', (_, jwe) => {
    expect(codesOf(zCompactJwe, jwe)).toEqual(invalidFormat('jwe'))
  })
})

describe('empty strings', () => {
  it.each(['kid', 'typ', 'zip'])('reports an empty JWE %s as too_small', (parameter) => {
    expect(codesOf(zJweHeader, { alg: 'ECDH-ES', enc: 'A128GCM', [parameter]: '' })).toMatchObject([
      { code: 'too_small', path: [parameter] },
    ])
  })

  it('reports an apu that is not base64url as invalid_format', () => {
    expect(codesOf(zJweHeader, { alg: 'ECDH-ES', enc: 'A128GCM', apu: 'a+b' })).toMatchObject([
      { code: 'invalid_format', path: ['apu'] },
    ])
  })

  it.each(['jti', 'nonce'])('reports an empty %s claim as too_small', (claim) => {
    expect(codesOf(zJwtPayload, { [claim]: '' })).toMatchObject([{ code: 'too_small', path: [claim] }])
  })

  it.each(['kid', 'jkt'])('reports an empty cnf %s as too_small', (member) => {
    expect(codesOf(zJwtPayload, { cnf: { [member]: '' } })).toMatchObject([
      { code: 'too_small', path: ['cnf', member] },
    ])
  })
})

describe('a cnf claim', () => {
  const jwk = { kty: 'EC', crv: 'P-256', x: 'eA', y: 'eQ' }
  const didUrl = 'did:example:holder#key-1'
  const cnfCodes = (cnf: unknown) => codesOf(zJwtPayload, { cnf })

  it.each([
    ['a jwk', { jwk }],
    ['a jkt', { jkt: 'dGh1bWI' }],
    ['a kid that is a DID URL', { kid: didUrl }],
    ['a kid that selects the key of a jku', { jku: 'https://holder.example/jwks.json', kid: 'key-1' }],
    ['a kid with the jkt of the key it resolves to', { kid: didUrl, jkt: 'dGh1bWI' }],
  ])('accepts %s', (_, cnf) => {
    expect(cnfCodes(cnf)).toEqual([])
  })

  it.each([
    ['a jwk and a jkt', { jwk, jkt: 'dGh1bWI' }, ['cnf', 'jkt']],
    ['a jwk and a jku', { jwk, jku: 'https://holder.example/jwks.json' }, ['cnf', 'jku']],
    ['a jwe and a jkt', { jwe: 'eyJh..aXY.Y3Q.dGFn', jkt: 'dGh1bWI' }, ['cnf', 'jkt']],
    ['a jwk and a kid', { jwk, kid: didUrl }, ['cnf', 'kid']],
    ['a jwe and a kid', { jwe: 'eyJh..aXY.Y3Q.dGFn', kid: didUrl }, ['cnf', 'kid']],
  ])('reports %s as not_allowed', (_, cnf, path) => {
    expect(cnfCodes(cnf)).toEqual([{ code: 'not_allowed', path, context: undefined }])
  })
})
