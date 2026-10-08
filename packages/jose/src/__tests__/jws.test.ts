import { base64url, stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { JoseParseError, JoseValidationError } from '../error'
import { parseJws } from '../jws/parse-jws'
import { signCompactJws } from '../jws/sign-jws'
import { jwsSignerFromHeader } from '../jws/signer'
import { assertJwsAlgorithmAllowed, verifyJwsSignature } from '../jws/verify-jws'
import type { FlattenedJws } from '../jws/z-jws'
import { verifyJwt } from '../jwt/verify-jwt'
import { certificateChain } from './certificates'
import { createEs256Context, unsignedCompactJws } from './context'

describe('parseJws', () => {
  it('rejects a JWS with alg none', () => {
    expect(() => parseJws({ jws: unsignedCompactJws({ alg: 'none' }, { iss: 'https://example.com' }) })).toThrow(
      `value may not be 'none'`
    )
  })

  it('rejects a JWS whose alg only differs from none in casing', () => {
    expect(() => parseJws({ jws: unsignedCompactJws({ alg: 'None' }, {}) })).toThrow(`value may not be 'none'`)
  })

  it('rejects a jwk header parameter carrying private key material', () => {
    const jws = unsignedCompactJws({ alg: 'ES256', jwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', d: 'd' } }, {})

    expect(() => parseJws({ jws })).toThrow(`contains the private key member(s) 'd'`)
  })

  it('validates against the registered header parameters even when a custom schema is given', async () => {
    const z = await import('zod')
    // A schema that says nothing about `alg` must not be able to let an unsecured JWS through
    const looseSchema = z.default.object({ typ: z.default.string() }).loose()

    expect(() =>
      parseJws({ jws: unsignedCompactJws({ alg: 'none', typ: 'my+jwt' }, {}), protectedHeaderSchema: looseSchema })
    ).toThrow(`value may not be 'none'`)
  })

  describe('crit', () => {
    it('rejects a critical header parameter that is not understood', () => {
      const jws = unsignedCompactJws({ alg: 'ES256', crit: ['sigD'], sigD: { mId: 'urn:example' } }, {})

      expect(() => parseJws({ jws })).toThrow(`lists 'sigD', which is not understood`)
    })

    it('accepts a critical header parameter that is understood', () => {
      const jws = unsignedCompactJws({ alg: 'ES256', crit: ['sigD'], sigD: { mId: 'urn:example' } }, {})

      expect(parseJws({ jws, understoodCriticalParameters: ['sigD'] }).protectedHeader.crit).toEqual(['sigD'])
    })

    it('rejects a critical header parameter that is not in the header', () => {
      const jws = unsignedCompactJws({ alg: 'ES256', crit: ['sigD'] }, {})

      expect(() => parseJws({ jws, understoodCriticalParameters: ['sigD'] })).toThrow(
        `the header does not contain that parameter`
      )
    })

    it('rejects a registered header parameter marked as critical', () => {
      const jws = unsignedCompactJws({ alg: 'ES256', typ: 'my+jwt', crit: ['typ'] }, {})

      expect(() => parseJws({ jws, understoodCriticalParameters: ['typ'] })).toThrow(
        `is a registered header parameter and must not be listed`
      )
    })

    it('rejects crit in the unprotected header', () => {
      const protectedHeader = base64url.encode(stringToBytes(JSON.stringify({ alg: 'ES256' })))

      expect(() =>
        parseJws({
          jws: {
            protected: protectedHeader,
            header: { crit: ['sigD'] },
            payload: base64url.encode(stringToBytes('{}')),
            signature: 'c2ln',
          },
        })
      ).toThrow('present in the unprotected header')
    })
  })

  describe('JSON serializations', () => {
    const protectedHeader = base64url.encode(stringToBytes(JSON.stringify({ alg: 'ES256' })))
    const payload = base64url.encode(stringToBytes('{"iss":"https://example.com"}'))

    it('parses a flattened JWS', () => {
      const parsed = parseJws({ jws: { protected: protectedHeader, payload, signature: 'c2ln', header: { kid: '1' } } })

      expect(parsed.serialization).toBe('flattened')
      expect(parsed.unprotectedHeader).toEqual({ kid: '1' })
      expect(parsed.signingInput).toBe(`${protectedHeader}.${payload}`)
      expect(parsed.compact).toBeUndefined()
    })

    it('parses the requested signature of a general JWS', () => {
      const otherProtectedHeader = base64url.encode(stringToBytes(JSON.stringify({ alg: 'ES384' })))
      const parsed = parseJws({
        jws: {
          payload,
          signatures: [
            { protected: protectedHeader, signature: 'c2ln' },
            { protected: otherProtectedHeader, signature: 'c2ln2' },
          ],
        },
        signatureIndex: 1,
      })

      expect(parsed.protectedHeader.alg).toBe('ES384')
      expect(parsed.signature).toBe('c2ln2')
    })

    it('rejects a signature index the general JWS does not have', () => {
      expect(() =>
        parseJws({
          jws: { payload, signatures: [{ protected: protectedHeader, signature: 'c2ln' }] },
          signatureIndex: 1,
        })
      ).toThrow(
        new JoseParseError(
          'Unable to parse the JWS, it does not contain a signature at index 1. It contains 1 signature(s).'
        )
      )
    })

    it('rejects a header parameter present in both the protected and the unprotected header', () => {
      expect(() =>
        parseJws({ jws: { protected: protectedHeader, header: { alg: 'ES384' }, payload, signature: 'c2ln' } })
      ).toThrow('must be disjoint')
    })

    it('rejects a JWS without a protected header', () => {
      expect(() => parseJws({ jws: { header: { alg: 'ES256' }, payload, signature: 'c2ln' } })).toThrow(
        'does not have a protected header'
      )
    })
  })

  // An empty signature is how an unsecured JWS is serialized, and `alg: none` is never accepted, so
  // there is nothing for a verification callback to check.
  describe('an empty signature', () => {
    const protectedHeader = base64url.encode(stringToBytes(JSON.stringify({ alg: 'ES256' })))
    const payload = base64url.encode(stringToBytes('{"iss":"https://example.com"}'))

    it('rejects a compact JWS whose signature part is empty', () => {
      expect(() => parseJws({ jws: `${protectedHeader}.${payload}.` })).toThrow(
        new JoseParseError('Unable to parse the JWS, it does not have a signature. An unsecured JWS is not supported.')
      )
    })

    it('rejects a flattened JWS whose signature is empty', () => {
      expect(() => parseJws({ jws: { protected: protectedHeader, payload, signature: '' } })).toThrow(
        JoseValidationError
      )
    })

    it('rejects a general JWS whose signature is empty', () => {
      expect(() => parseJws({ jws: { payload, signatures: [{ protected: protectedHeader, signature: '' }] } })).toThrow(
        JoseValidationError
      )
    })

    it('rejects a JWT whose signature is empty before the verification callback is called', async () => {
      let calls = 0
      const jwt = `${protectedHeader}.${payload}.`

      await expect(
        verifyJwt({
          jwt,
          verifyJwsCallback: () => {
            calls++
            return { verified: true, signerJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } }
          },
        })
      ).rejects.toThrow(JoseParseError)
      expect(calls).toBe(0)
    })
  })

  describe('a JSON serialized JWS that is not an object', () => {
    // What `JSON.parse` of an untrusted body can return
    it.each([{ jws: null }, { jws: 42 }, { jws: true }, { jws: undefined }, { jws: [] }])('rejects $jws', ({ jws }) => {
      expect(() => parseJws({ jws: jws as unknown as FlattenedJws })).toThrow(
        new JoseParseError('Unable to parse the JWS, a JSON serialized JWS must be an object')
      )
    })
  })

  describe('detached and unencoded payloads', () => {
    it('uses the detached payload for the signing input', () => {
      const header = base64url.encode(stringToBytes(JSON.stringify({ alg: 'ES256' })))
      const parsed = parseJws({ jws: `${header}..c2ln`, detachedPayload: 'the payload' })

      expect(parsed.signingInput).toBe(`${header}.${base64url.encode(stringToBytes('the payload'))}`)
      expect(parsed.payload).toEqual(stringToBytes('the payload'))
    })

    it('rejects a detached payload for a JWS that carries one', () => {
      expect(() => parseJws({ jws: unsignedCompactJws({ alg: 'ES256' }, {}), detachedPayload: 'the payload' })).toThrow(
        'Only one of the two can be the payload that was signed'
      )
    })

    it('rejects b64 false when it is not marked critical', () => {
      const jws = unsignedCompactJws({ alg: 'ES256', b64: false }, {})

      expect(() => parseJws({ jws })).toThrow(`is not listed in the 'crit' header parameter`)
    })

    it('signs over the unencoded payload when b64 is false', () => {
      const header = base64url.encode(stringToBytes(JSON.stringify({ alg: 'ES256', b64: false, crit: ['b64'] })))
      const parsed = parseJws({
        jws: `${header}.$.eyJhbGciOiJFUzI1NiJ9`,
        understoodCriticalParameters: ['b64'],
      })

      expect(parsed.signingInput).toBe(`${header}.$`)
      expect(parsed.payload).toEqual(stringToBytes('$'))
    })
  })
})

describe('jwsSignerFromHeader', () => {
  it('establishes an x5c signer', () => {
    expect(jwsSignerFromHeader({ header: { alg: 'ES256', x5c: certificateChain } })).toEqual({
      method: 'x5c',
      alg: 'ES256',
      x5c: certificateChain,
      kid: undefined,
    })
  })

  it('establishes a did signer from a did in iss and a fragment in kid', () => {
    expect(jwsSignerFromHeader({ header: { alg: 'ES256', kid: '#key-1' }, issuer: 'did:example:1' })).toEqual({
      method: 'did',
      alg: 'ES256',
      didUrl: 'did:example:1#key-1',
    })
  })

  it('falls back to a custom signer', () => {
    expect(jwsSignerFromHeader({ header: { alg: 'ES256', kid: 'key-1' } })).toEqual({
      method: 'custom',
      alg: 'ES256',
      kid: 'key-1',
    })
  })

  it('rejects a header that identifies the signer in more than one way', () => {
    const header = { alg: 'ES256', x5c: certificateChain, jwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } }

    expect(() => jwsSignerFromHeader({ header })).toThrow('identifies the signer in 2 ways')
  })

  it('resolves the ambiguity when the caller narrows the allowed methods', () => {
    const header = { alg: 'ES256', x5c: certificateChain, jwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } }

    expect(jwsSignerFromHeader({ header, allowedSignerMethods: ['x5c'] }).method).toBe('x5c')
  })

  it('rejects a signer method that is not allowed', () => {
    expect(() =>
      jwsSignerFromHeader({ header: { alg: 'ES256', x5c: certificateChain }, allowedSignerMethods: ['jwk'] })
    ).toThrow('signer method(s) that are not allowed')
  })
})

describe('assertJwsAlgorithmAllowed', () => {
  it('applies the allowed algorithms and rejects symmetric algorithms unless allowed', () => {
    expect(() => assertJwsAlgorithmAllowed({ alg: 'ES256' })).not.toThrow()
    expect(() => assertJwsAlgorithmAllowed({ alg: 'ES256', allowedAlgorithms: ['EdDSA'] })).toThrow(
      `The JWS uses alg 'ES256', but the allowed algorithms are 'EdDSA'`
    )
    expect(() => assertJwsAlgorithmAllowed({ alg: 'HS256' })).toThrow(`symmetric algorithm 'HS256'`)
    expect(() => assertJwsAlgorithmAllowed({ alg: 'HS256', allowSymmetricAlgorithms: true })).not.toThrow()
  })
})

describe('signCompactJws and verifyJwsSignature', () => {
  it('signs and verifies a JWS', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()

    const { compact } = await signCompactJws({
      protectedHeader: { alg: 'ES256', typ: 'example+jws' },
      payload: { hello: 'world' },
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
    })

    const parsed = parseJws({ jws: compact })
    const { signer } = await verifyJwsSignature({ jws: parsed, verifyJwsCallback: verifyJws })

    expect(signer.publicJwk).toEqual(publicJwk)
    expect(parsed.payload).toEqual(stringToBytes('{"hello":"world"}'))
  })

  it('signs and verifies a JWS with a detached payload', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()

    const { compact } = await signCompactJws({
      protectedHeader: { alg: 'ES256' },
      payload: 'the payload',
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
      detachPayload: true,
    })

    expect(compact.split('.')[1]).toBe('')

    const parsed = parseJws({ jws: compact, detachedPayload: 'the payload' })
    await expect(verifyJwsSignature({ jws: parsed, verifyJwsCallback: verifyJws })).resolves.toBeDefined()

    const withOtherPayload = parseJws({ jws: compact, detachedPayload: 'another payload' })
    await expect(verifyJwsSignature({ jws: withOtherPayload, verifyJwsCallback: verifyJws })).rejects.toThrow(
      'Error during verification of the JWS'
    )
  })

  it('refuses to sign a JWS with alg none', async () => {
    const { signJws, publicJwk } = await createEs256Context()

    await expect(
      signCompactJws({
        protectedHeader: { alg: 'none' },
        payload: {},
        signer: { method: 'jwk', alg: 'none', publicJwk },
        signJwsCallback: signJws,
      })
    ).rejects.toThrow(`value may not be 'none'`)
  })

  it('rejects an algorithm the caller does not allow', async () => {
    const { verifyJws } = await createEs256Context()
    const parsed = parseJws({ jws: unsignedCompactJws({ alg: 'ES256' }, {}) })

    await expect(
      verifyJwsSignature({ jws: parsed, verifyJwsCallback: verifyJws, allowedAlgorithms: ['ES384'] })
    ).rejects.toThrow(`uses alg 'ES256', but the allowed algorithms are 'ES384'`)
  })

  it('rejects a symmetric algorithm unless it is allowed', async () => {
    const { verifyJws } = await createEs256Context()
    const parsed = parseJws({ jws: unsignedCompactJws({ alg: 'HS256' }, {}) })

    await expect(verifyJwsSignature({ jws: parsed, verifyJwsCallback: verifyJws })).rejects.toThrow(
      `uses the symmetric algorithm 'HS256'`
    )
  })

  it('rejects a key that cannot be used with the algorithm of the token', async () => {
    const parsed = parseJws({ jws: unsignedCompactJws({ alg: 'ES256' }, {}) })

    // A verification callback that reports having verified with an RSA key, while the token claims
    // to use ECDSA: the two cannot both be true.
    await expect(
      verifyJwsSignature({
        jws: parsed,
        verifyJwsCallback: () => ({ verified: true, signerJwk: { kty: 'RSA', n: 'n', e: 'AQAB' } }),
      })
    ).rejects.toThrow(`requires a key with kty 'EC'`)
  })
})
