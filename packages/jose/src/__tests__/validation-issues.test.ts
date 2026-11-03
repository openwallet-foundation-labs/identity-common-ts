import { base64url, parseWithSchema, stringToBytes, ValidationError, zTyp } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import z from 'zod'
import { JoseValidationError } from '../error'
import { zJweAlg, zJwsAlg } from '../jwa/z-alg'
import { zX5cCertificate } from '../jwk/z-x5c'
import { assertCriticalHeaderParameters } from '../jws/critical-headers'
import { parseJws } from '../jws/parse-jws'
import { zCompactJws, zJwsProtectedHeader } from '../jws/z-jws'

const encode = (value: unknown) => base64url.encode(stringToBytes(JSON.stringify(value)))
const compactJws = (header: unknown) => `${encode(header)}.${encode({})}.c2ln`

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

describe('a JWS whose header does not validate', () => {
  it('throws a JoseValidationError with the issues of the header', () => {
    const error = errorOf(() => parseJws({ jws: compactJws({ alg: 'none' }) }))

    expect(error).toBeInstanceOf(JoseValidationError)
    expect(error).toBeInstanceOf(ValidationError)
    expect((error as JoseValidationError).issues).toMatchObject([
      { severity: 'error', code: 'invalid_value', path: ['alg'] },
    ])
  })

  it('reports a typ the caller does not expect as invalid_typ', () => {
    const protectedHeaderSchema = z.object({ ...zJwsProtectedHeader.shape, typ: zTyp('kb+jwt') }).loose()
    const error = errorOf(() => parseJws({ jws: compactJws({ alg: 'ES256', typ: 'JWT' }), protectedHeaderSchema }))

    expect((error as JoseValidationError).issues).toMatchObject([
      { code: 'invalid_typ', path: ['typ'], context: { expected: ['kb+jwt'], actual: 'JWT' } },
    ])
  })
})

describe('the codes of the jose schemas', () => {
  it.each(['none', 'NONE'])('reports alg %s as invalid_value', (alg) => {
    expect(codesOf(zJwsAlg, alg)).toEqual([{ code: 'invalid_value', path: [] }])
    expect(codesOf(zJweAlg, alg)).toEqual([{ code: 'invalid_value', path: [] }])
  })

  it('reports a certificate that is not standard base64 as invalid_format base64', () => {
    expect(codesOf(zX5cCertificate, 'MII_')).toEqual([
      { code: 'invalid_format', path: [], context: { format: 'base64' } },
    ])
  })

  it('reports a certificate that is not a DER SEQUENCE as invalid_format der', () => {
    expect(codesOf(zX5cCertificate, 'AAAA')).toEqual([{ code: 'invalid_format', path: [], context: { format: 'der' } }])
  })

  // A validator that parses with its own `codes` rejects a custom issue without one
  it('can be part of a validator with its own codes', () => {
    const schema = z.object({ alg: zJwsAlg, x5c: z.array(zX5cCertificate) })

    expect(parseWithSchema(schema, { alg: 'none', x5c: ['AAAA'] }, { codes: {} })).toMatchObject({
      success: false,
      issues: [
        { code: 'invalid_value', path: ['alg'] },
        { code: 'invalid_format', path: ['x5c', 0] },
      ],
    })
  })
})

describe('a crit header parameter that does not verify', () => {
  it('reports an issue for each listed parameter, rather than only the first', () => {
    const error = errorOf(() =>
      assertCriticalHeaderParameters({
        protectedHeader: { alg: 'ES256', crit: ['alg', 'absent', 'ext'], ext: true },
        understoodCriticalParameters: ['b64'],
      })
    )

    expect(error).toBeInstanceOf(JoseValidationError)
    expect((error as JoseValidationError).issues).toMatchObject([
      { code: 'invalid_crit', path: ['crit', 0], context: { parameter: 'alg' } },
      { code: 'invalid_crit', path: ['crit', 1], context: { parameter: 'absent' } },
      { code: 'unsupported_crit', path: ['crit', 2], context: { parameter: 'ext', understood: ['b64'] } },
    ])
  })

  // RFC 7797 unencoded payloads are opt-in
  it('says how to accept b64 when it is not understood', () => {
    const error = errorOf(() =>
      assertCriticalHeaderParameters({ protectedHeader: { alg: 'ES256', b64: false, crit: ['b64'] } })
    ) as JoseValidationError

    expect(error.issues).toMatchObject([
      {
        code: 'unsupported_crit',
        path: ['crit', 0],
        message: expect.stringContaining(`only accepted when 'b64' is in 'understoodCriticalParameters'`),
      },
    ])
  })
})

describe('zCompactJws', () => {
  it.each(['eyJh.eyJi.c2ln', 'eyJh..c2ln'])('accepts %s', (jws) => {
    expect(zCompactJws.safeParse(jws).success).toBe(true)
  })

  it.each(['eyJh.eyJi', '.eyJi.c2ln', 'eyJh.eyJi.', 'eyJh.eyJi.c2ln.x', 'eyJh.ey+i.c2ln', 'eyJh.eyJi.c2ln='])(
    'reports %s as invalid_format jws',
    (jws) => {
      expect(codesOf(zCompactJws, jws)).toEqual([{ code: 'invalid_format', path: [], context: { format: 'jws' } }])
    }
  )
})
