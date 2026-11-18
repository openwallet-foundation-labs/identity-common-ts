import { base64, base64url, concatBytes, stringToBytes, ValidationError, zTyp } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import z from 'zod'
import { JoseError, JoseParseError, JoseValidationError } from '../error'
import { parseJws } from '../jws/parse-jws'
import { zJwsProtectedHeader } from '../jws/z-jws'
import { decodeJwt } from '../jwt/decode-jwt'
import { validationIssue } from './context'

/**
 * What `parseJws` and `decodeJwt` accept, down to the byte: two encodings that decode to the same
 * header would be two tokens that are treated as one.
 */

/** Matches a thrown error by its class and a part of its message. */
const joseError = (type: { name: string }, message: string) =>
  expect.objectContaining({ name: type.name, message: expect.stringContaining(message) })

const encodeJson = (value: unknown) => base64url.encode(stringToBytes(JSON.stringify(value)))
const encodeText = (text: string) => base64url.encode(stringToBytes(text))

/** base64url of `text` with the raw `bytes` spliced in where `text` has `%s`. */
const encodeWithBytes = (text: string, bytes: number[]) => {
  const [before, after] = text.split('%s')
  return base64url.encode(concatBytes(stringToBytes(before), new Uint8Array(bytes), stringToBytes(after)))
}

/** The error `fn` throws, so that more than its message can be looked at. */
const errorThrownBy = (fn: () => unknown): unknown => {
  try {
    fn()
  } catch (error) {
    return error
  }
  throw new Error('Expected the function to throw')
}

const header = encodeJson({ alg: 'ES256' })
const payload = encodeJson({ iss: 'https://issuer.example' })
const signature = 'c2lnbmF0dXJl'

describe('the base64url alphabet', () => {
  it('rejects a header encoded with the standard base64 alphabet where it differs by a slash', () => {
    // '???' encodes to '/' in the standard alphabet and to '_' in the base64url one
    const standardHeader = base64.encode(stringToBytes(JSON.stringify({ alg: 'ES256', kid: '???' })))
    expect(standardHeader).toContain('/')

    expect(() => decodeJwt({ jwt: `${standardHeader}.${payload}.${signature}` })).toThrow(
      joseError(JoseParseError, 'the protected header of a compact JWS must be base64url')
    )
  })

  it('rejects a payload encoded with the standard base64 alphabet', () => {
    const standardPayload = base64.encode(stringToBytes(JSON.stringify({ iss: '~~a' }))).replace(/=+$/, '')
    expect(standardPayload).toContain('+')

    expect(() => decodeJwt({ jwt: `${header}.${standardPayload}.${signature}` })).toThrow(
      joseError(JoseParseError, 'Unable to decode the JWS payload, it is not valid base64url')
    )
  })

  it('rejects a signature with characters of the standard base64 alphabet', () => {
    expect(() => decodeJwt({ jwt: `${header}.${payload}.c2ln+/` })).toThrow(
      joseError(JoseParseError, 'the signature of a compact JWS must be base64url')
    )
  })
})

describe('padding', () => {
  it('rejects a padded payload', () => {
    expect(() => decodeJwt({ jwt: `${header}.${encodeJson({ a: 1 })}=.${signature}` })).toThrow(
      joseError(JoseParseError, 'Unable to decode the JWS payload, it is not valid base64url')
    )
  })

  it('rejects a padded signature', () => {
    expect(() => decodeJwt({ jwt: `${header}.${payload}.c2lnbmF0dXJlMQ==` })).toThrow(
      joseError(JoseParseError, 'the signature of a compact JWS must be base64url')
    )
  })

  it('rejects a header whose length leaves a single trailing character, which encodes no byte', () => {
    expect(header.length % 4).toBe(0)

    expect(() => decodeJwt({ jwt: `${header}A.${payload}.${signature}` })).toThrow(
      joseError(JoseParseError, 'the protected header of a compact JWS must be base64url')
    )
  })
})

describe('UTF-8', () => {
  it.each([
    ['a byte that never occurs in UTF-8', [0xff]],
    ['an overlong encoding of a slash', [0xc0, 0xaf]],
    ['an encoded UTF-16 surrogate', [0xed, 0xa0, 0x80]],
    ['a lead byte without its continuation byte', [0xc3, 0x28]],
  ])('rejects a header with %s', (_description, bytes) => {
    const invalidHeader = encodeWithBytes('{"alg":"ES256","kid":"%s"}', bytes)

    expect(() => decodeJwt({ jwt: `${invalidHeader}.${payload}.${signature}` })).toThrow(
      joseError(JoseParseError, 'Unable to decode the JWS protected header, it is not valid base64url encoded JSON')
    )
  })

  it('rejects a payload with a lead byte without its continuation byte', () => {
    const invalidPayload = encodeWithBytes('{"iss":"%s"}', [0xc3, 0x28])

    expect(() => decodeJwt({ jwt: `${header}.${invalidPayload}.${signature}` })).toThrow(
      joseError(JoseParseError, 'Unable to decode the JWT payload, it is not valid base64url encoded JSON')
    )
  })

  it('rejects a header that starts with a byte order mark', () => {
    const headerWithBom = encodeWithBytes('%s{"alg":"ES256"}', [0xef, 0xbb, 0xbf])

    expect(() => decodeJwt({ jwt: `${headerWithBom}.${payload}.${signature}` })).toThrow(
      joseError(JoseParseError, 'Unable to decode the JWS protected header, it is not valid base64url encoded JSON')
    )
  })

  it('decodes characters outside ASCII in the header and the payload', () => {
    const jwt = `${encodeJson({ alg: 'ES256', kid: 'Jöhn 🦋' })}.${encodeJson({ name: 'Jöhn 🦋', greeting: 'שלום' })}.${signature}`

    const decoded = decodeJwt({ jwt })

    expect([decoded.header.kid, decoded.payload]).toEqual(['Jöhn 🦋', { name: 'Jöhn 🦋', greeting: 'שלום' }])
  })
})

describe('JSON', () => {
  it.each([
    ['a string', 'ES256'],
    ['a number', 256],
    ['null', null],
    ['true', true],
    ['an array', [{ alg: 'ES256' }]],
  ])('rejects a header that is %s rather than an object', (_description, value) => {
    expect(() => decodeJwt({ jwt: `${encodeJson(value)}.${payload}.${signature}` })).toThrow(
      joseError(JoseParseError, 'Unable to decode the JWS protected header, it is not a JSON object')
    )
  })

  it.each([
    ['a string', 'https://issuer.example'],
    ['a number', 42],
    ['null', null],
    ['an array', [{ iss: 'https://issuer.example' }]],
  ])('rejects a JWT payload that is %s rather than an object', (_description, value) => {
    expect(() => decodeJwt({ jwt: `${header}.${encodeJson(value)}.${signature}` })).toThrow(
      joseError(JoseParseError, 'Unable to decode the JWT payload, it is not a JSON object')
    )
  })

  it('rejects a JWT payload that is not JSON', () => {
    expect(() => decodeJwt({ jwt: `${header}.${encodeText('{not json')}.${signature}` })).toThrow(
      joseError(JoseParseError, 'Unable to decode the JWT payload, it is not valid base64url encoded JSON')
    )
  })

  it('returns a JWS payload that is not JSON as it is', () => {
    expect(parseJws({ jws: `${header}.${encodeText('not json')}.${signature}` }).payload).toEqual(
      stringToBytes('not json')
    )
  })

  it('rejects a header whose last alg member is none', () => {
    // JSON.parse keeps the last of two members with the same name, which RFC 7515 allows a parser to
    // do, so it is that one that has to be checked
    const duplicateAlg = encodeText('{"alg":"ES256","alg":"none"}')

    expect(() => decodeJwt({ jwt: `${duplicateAlg}.${payload}.${signature}` })).toThrow(
      validationIssue(['alg'], 'invalid_value')
    )
  })

  it('rejects an exp that JSON reads as Infinity', () => {
    expect(() => decodeJwt({ jwt: `${header}.${encodeText('{"exp":1e400}')}.${signature}` })).toThrow(
      joseError(JoseValidationError, 'Invalid JWT payload')
    )
  })
})

describe('the compact serialization', () => {
  it.each([
    ['an empty string', ''],
    ['two parts', `${header}.${payload}`],
    ['four parts', `${header}.${payload}.${signature}.${signature}`],
    ['the five parts of a compact JWE', `${header}..aXY.Y3Q.dGFn`],
  ])('rejects %s', (_description, jwt) => {
    expect(() => decodeJwt({ jwt })).toThrow(
      joseError(JoseParseError, 'a compact JWS must consist of exactly three parts')
    )
  })

  it('rejects a token whose header part is empty', () => {
    expect(() => decodeJwt({ jwt: `.${payload}.${signature}` })).toThrow(
      joseError(JoseParseError, 'it does not have a protected header')
    )
  })

  it('rejects leading whitespace', () => {
    expect(() => decodeJwt({ jwt: ` ${header}.${payload}.${signature}` })).toThrow(
      joseError(JoseParseError, 'the protected header of a compact JWS must be base64url')
    )
  })

  it('rejects a trailing line break', () => {
    expect(() => decodeJwt({ jwt: `${header}.${payload}.${signature}\n` })).toThrow(
      joseError(JoseParseError, 'the signature of a compact JWS must be base64url')
    )
  })

  it('rejects whitespace inside the payload part', () => {
    expect(() => decodeJwt({ jwt: `${header}.${payload.slice(0, 4)} ${payload.slice(4)}.${signature}` })).toThrow(
      joseError(JoseParseError, 'Unable to decode the JWS payload, it is not valid base64url')
    )
  })

  it('rejects a character outside ASCII in the header part', () => {
    expect(() => decodeJwt({ jwt: `${header}é.${payload}.${signature}` })).toThrow(
      joseError(JoseParseError, 'the protected header of a compact JWS must be base64url')
    )
  })

  it('decodes a token whose payload is a megabyte long', () => {
    const data = 'a'.repeat(1_000_000)

    expect(decodeJwt({ jwt: `${header}.${encodeJson({ data })}.${signature}` }).payload.data).toBe(data)
  })
})

describe('crit', () => {
  const registeredParameters = [
    'alg',
    'jku',
    'jwk',
    'kid',
    'x5u',
    'x5c',
    'x5t',
    'x5t#S256',
    'typ',
    'cty',
    'crit',
    'enc',
    'zip',
    'epk',
    'apu',
    'apv',
    'iv',
    'tag',
    'p2s',
    'p2c',
  ]

  it.each(registeredParameters)('rejects the registered header parameter %s marked as critical', (name) => {
    const jws = `${encodeJson({ alg: 'ES256', crit: [name] })}.${payload}.${signature}`

    expect(() => parseJws({ jws, understoodCriticalParameters: [name] })).toThrow(
      validationIssue(['crit', 0], 'invalid_crit')
    )
  })

  it.each([
    ['empty', []],
    ['holding an empty name', ['']],
    ['a string rather than an array', 'b64'],
  ])('rejects a crit that is %s', (_description, crit) => {
    expect(() => parseJws({ jws: `${encodeJson({ alg: 'ES256', crit })}.${payload}.${signature}` })).toThrow(
      joseError(JoseValidationError, 'Invalid JWS protected header')
    )
  })

  it('rejects the critical parameter that is not understood when only some of them are', () => {
    const jws = `${encodeJson({ alg: 'ES256', crit: ['sigT', 'sigD'], sigT: '2026-09-15T12:00:00Z', sigD: {} })}.${payload}.${signature}`

    expect(() => parseJws({ jws, understoodCriticalParameters: ['sigT'] })).toThrow(
      validationIssue(['crit', 1], 'unsupported_crit')
    )
  })

  it('accepts several critical parameters that are all understood', () => {
    const jws = `${encodeJson({ alg: 'ES256', crit: ['sigT', 'sigD'], sigT: '2026-09-15T12:00:00Z', sigD: {} })}.${payload}.${signature}`

    expect(parseJws({ jws, understoodCriticalParameters: ['sigD', 'sigT'] }).protectedHeader.crit).toEqual([
      'sigT',
      'sigD',
    ])
  })

  it('rejects crit in the unprotected header of a signature of a general JWS', () => {
    const jws = { payload, signatures: [{ protected: header, header: { crit: ['sigD'], sigD: {} }, signature }] }

    expect(() => parseJws({ jws, understoodCriticalParameters: ['sigD'] })).toThrow(
      validationIssue(['crit'], 'invalid_crit')
    )
  })

  it('accepts a critical parameter carried in the unprotected header when it is understood', () => {
    const jws = { protected: encodeJson({ alg: 'ES256', crit: ['sigD'] }), header: { sigD: {} }, payload, signature }

    expect(parseJws({ jws, understoodCriticalParameters: ['sigD'] }).unprotectedHeader).toEqual({ sigD: {} })
  })

  it('reads a b64 of true marked as critical as a base64url encoded payload', () => {
    const jws = `${encodeJson({ alg: 'ES256', b64: true, crit: ['b64'] })}.${payload}.${signature}`

    expect(parseJws({ jws, understoodCriticalParameters: ['b64'] }).payload).toEqual(
      stringToBytes('{"iss":"https://issuer.example"}')
    )
  })

  it('rejects a b64 that is not a boolean', () => {
    const jws = `${encodeJson({ alg: 'ES256', b64: 'false', crit: ['b64'] })}.${payload}.${signature}`

    expect(() => parseJws({ jws, understoodCriticalParameters: ['b64'] })).toThrow(
      joseError(JoseValidationError, 'Invalid JWS protected header')
    )
  })
})

describe('the protected and the unprotected header', () => {
  it('rejects parameters present in both headers, naming each of them', () => {
    const jws = {
      protected: encodeJson({ alg: 'ES256', kid: 'key-1', typ: 'example+jwt' }),
      header: { typ: 'other+jwt', kid: 'key-2' },
      payload,
      signature,
    }

    expect(() => parseJws({ jws })).toThrow(
      joseError(
        JoseParseError,
        `the header parameter(s) 'typ', 'kid' are present in both the protected and the unprotected header`
      )
    )
  })

  it('rejects a JWS whose alg is only in the unprotected header', () => {
    const jws = { protected: encodeJson({ typ: 'example+jwt' }), header: { alg: 'ES256' }, payload, signature }

    expect(() => parseJws({ jws })).toThrow(joseError(JoseValidationError, 'Invalid JWS protected header'))
  })

  it('does not satisfy a protected header schema with a typ that is only in the unprotected header', () => {
    const protectedHeaderSchema = z.object({ ...zJwsProtectedHeader.shape, typ: zTyp('example+jwt') }).loose()
    const jws = { protected: header, header: { typ: 'example+jwt' }, payload, signature }

    expect(() => parseJws({ jws, protectedHeaderSchema })).toThrow(
      joseError(JoseValidationError, 'Invalid JWS protected header')
    )
  })

  it('ignores a b64 of false that is only in the unprotected header', () => {
    const jws = { protected: header, header: { b64: false }, payload, signature }

    expect(parseJws({ jws }).payload).toEqual(stringToBytes('{"iss":"https://issuer.example"}'))
  })

  it('rejects a flattened JWS whose protected header is empty', () => {
    expect(() => parseJws({ jws: { protected: '', header: { alg: 'ES256' }, payload, signature } })).toThrow(
      joseError(JoseParseError, 'it does not have a protected header')
    )
  })
})

describe('typ, compared as a media type', () => {
  const headerSchemaFor = (...expected: [string, ...string[]]) =>
    z.object({ ...zJwsProtectedHeader.shape, typ: zTyp(...expected) }).loose()
  const tokenWithTyp = (typ: string) => `${encodeJson({ alg: 'ES256', typ })}.${payload}.${signature}`

  it('accepts the expected typ in another casing', () => {
    expect(() =>
      decodeJwt({ jwt: tokenWithTyp('Example+JWT'), headerSchema: headerSchemaFor('example+jwt') })
    ).not.toThrow()
  })

  it('accepts a typ without the application prefix when the expected type has it', () => {
    expect(() =>
      decodeJwt({ jwt: tokenWithTyp('example+jwt'), headerSchema: headerSchemaFor('application/example+jwt') })
    ).not.toThrow()
  })

  it('accepts any one of several expected types', () => {
    expect(() =>
      decodeJwt({ jwt: tokenWithTyp('other+jwt'), headerSchema: headerSchemaFor('example+jwt', 'other+jwt') })
    ).not.toThrow()
  })

  it('returns the typ as it was received rather than normalized', () => {
    const { header } = decodeJwt({
      jwt: tokenWithTyp('Application/Example+JWT'),
      headerSchema: headerSchemaFor('example+jwt'),
    })

    expect(header.typ).toBe('Application/Example+JWT')
  })

  it.each([
    ['only starts with the expected type', 'example+jwt2', 'invalid_typ'],
    ['has media type parameters', 'example+jwt; charset=utf-8', 'invalid_typ'],
    ['is empty', '', 'too_small'],
  ] as const)('rejects a typ that %s', (_description, typ, code) => {
    expect(() => decodeJwt({ jwt: tokenWithTyp(typ), headerSchema: headerSchemaFor('example+jwt') })).toThrow(
      validationIssue(['typ'], code)
    )
  })
})

describe('the errors a malformed token raises', () => {
  const tokenWithNumericAlg = `${encodeJson({ alg: 256 })}.${payload}.${signature}`

  it('carries the issues of the schema on a validation error', () => {
    const error = errorThrownBy(() => decodeJwt({ jwt: tokenWithNumericAlg }))

    expect(error).toMatchObject({ issues: [expect.objectContaining({ code: 'invalid_type', path: ['alg'] })] })
  })

  it('raises a validation error that is the ValidationError of identity-common rather than a JoseError', () => {
    const error = errorThrownBy(() => decodeJwt({ jwt: tokenWithNumericAlg }))

    expect(error).toBeInstanceOf(ValidationError)
    expect(error).not.toBeInstanceOf(JoseError)
  })

  it('raises a critical parameter that is not understood as a validation error', () => {
    const jwt = `${encodeJson({ alg: 'ES256', crit: ['sigD'], sigD: {} })}.${payload}.${signature}`
    const error = errorThrownBy(() => decodeJwt({ jwt }))

    expect(error).toBeInstanceOf(JoseValidationError)
    expect((error as JoseValidationError).findIssue('unsupported_crit')?.context).toEqual({
      parameter: 'sigD',
      understood: [],
    })
  })
})
