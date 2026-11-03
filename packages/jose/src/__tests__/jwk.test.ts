import { type Hasher, parseWithSchema, stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { JoseSignerError } from '../error'
import { extractJwkFromJwkSet, isJwkInSet } from '../jwk/jwks'
import { calculateJwkThumbprint, calculateJwkThumbprintUri } from '../jwk/thumbprint'
import { zPublicJwk } from '../jwk/z-jwk'

const hashCallback: Hasher = async (data, alg) =>
  new Uint8Array(
    await globalThis.crypto.subtle.digest(alg.toUpperCase(), typeof data === 'string' ? stringToBytes(data) : data)
  )

describe('calculateJwkThumbprint', () => {
  // The example key and its thumbprint from RFC 7638 section 3.1
  const rsaJwk = {
    kty: 'RSA',
    n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
    e: 'AQAB',
    alg: 'RS256',
    kid: '2011-04-29',
  }

  it('matches the RFC 7638 test vector', async () => {
    const thumbprint = await calculateJwkThumbprint({
      jwk: rsaJwk,
      hashAlgorithm: 'sha-256',
      hashCallback,
    })

    expect(thumbprint).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs')
  })

  it('ignores the members that are not part of the thumbprint', async () => {
    const { alg: _alg, kid: _kid, ...withoutOptionalMembers } = rsaJwk

    expect(
      await calculateJwkThumbprint({
        jwk: withoutOptionalMembers,
        hashAlgorithm: 'sha-256',
        hashCallback,
      })
    ).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs')
  })

  it('builds a thumbprint URI as defined in RFC 9278', async () => {
    const uri = await calculateJwkThumbprintUri({ jwk: rsaJwk, hashAlgorithm: 'sha-256', hashCallback })

    expect(uri).toBe('urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs')
  })

  it('rejects a key that is missing a member the thumbprint is computed over', async () => {
    await expect(
      calculateJwkThumbprint({
        jwk: { kty: 'EC', crv: 'P-256', x: 'x' },
        hashAlgorithm: 'sha-256',
        hashCallback,
      })
    ).rejects.toThrow('Unable to calculate the thumbprint')
  })
})

describe('zPublicJwk', () => {
  it('accepts a public key', () => {
    expect(zPublicJwk.safeParse({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }).success).toBe(true)
  })

  it('rejects a private key', () => {
    const result = zPublicJwk.safeParse({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', d: 'd' })

    expect(result.success).toBe(false)
    expect(result.error?.issues[0].message).toContain(`private key member 'd'`)
  })

  it('reports each private key member as not_allowed at its path', () => {
    const result = parseWithSchema(zPublicJwk, { kty: 'RSA', n: 'n', e: 'e', d: 'd', p: 'p' })

    expect(result.success ? [] : result.issues.map(({ code, path }) => ({ code, path }))).toEqual([
      { code: 'not_allowed', path: ['d'] },
      { code: 'not_allowed', path: ['p'] },
    ])
  })

  it('rejects a symmetric key', () => {
    expect(parseWithSchema(zPublicJwk, { kty: 'oct', k: 'k' })).toMatchObject({
      success: false,
      issues: [{ code: 'not_allowed', path: ['k'] }],
    })
  })
})

describe('jwks', () => {
  const signingKey = { kty: 'EC', crv: 'P-256', x: 'x1', y: 'y1', kid: 'sig-1', use: 'sig' }
  const encryptionKey = { kty: 'EC', crv: 'P-256', x: 'x2', y: 'y2', kid: 'enc-1', use: 'enc' }

  it('selects the key with the given kid', () => {
    expect(extractJwkFromJwkSet({ jwks: { keys: [signingKey, encryptionKey] }, kid: 'sig-1', use: 'sig' })).toEqual(
      signingKey
    )
  })

  it('selects the only key for the use when no kid is given', () => {
    expect(extractJwkFromJwkSet({ jwks: { keys: [signingKey, encryptionKey] }, use: 'enc' })).toEqual(encryptionKey)
  })

  it('does not guess when more than one key is a candidate', () => {
    const jwks = { keys: [signingKey, { ...signingKey, kid: 'sig-2' }] }

    expect(() => extractJwkFromJwkSet({ jwks, use: 'sig' })).toThrow('No kid provided')
  })

  it('does not fall back to another key when the kid is not found', () => {
    expect(() => extractJwkFromJwkSet({ jwks: { keys: [signingKey] }, kid: 'other', use: 'sig' })).toThrow(
      `No key with kid 'other' found`
    )
  })

  it('compares keys in a set by thumbprint', async () => {
    const jwk = { kty: 'EC', crv: 'P-256', x: 'x1', y: 'y1' }
    // The same key, with members that are not part of the thumbprint
    const sameKey = { ...jwk, kid: 'other-kid', alg: 'ES256' }

    expect(await isJwkInSet({ jwk, jwks: [sameKey], hashCallback })).toBe(true)
    expect(await isJwkInSet({ jwk, jwks: [{ ...jwk, x: 'x2' }], hashCallback })).toBe(false)
  })
})

/**
 * Several keys in a set can carry the same kid, during a key rotation say. Picking the first would
 * verify against a key the issuer may not have signed with, so a kid that names more than one key is
 * ambiguous — unless the keys are the same JWK listed twice.
 */
describe('extractJwkFromJwkSet for a kid that more than one key in the set has', () => {
  const key = { kty: 'EC', crv: 'P-256', x: 'eDE', y: 'eTE', kid: 'key-1' }
  const otherKey = { kty: 'EC', crv: 'P-256', x: 'eDI', y: 'eTI', kid: 'key-1' }

  it('rejects the kid as ambiguous when the keys differ', () => {
    expect(() => extractJwkFromJwkSet({ jwks: { keys: [key, otherKey] }, kid: 'key-1', use: 'sig' })).toThrow(
      expect.objectContaining({
        name: JoseSignerError.name,
        message: expect.stringContaining(`The jwks contains 2 keys with kid 'key-1' that differ`),
      })
    )
  })

  it('rejects the kid as ambiguous whichever of the keys comes first', () => {
    expect(() => extractJwkFromJwkSet({ jwks: { keys: [otherKey, key] }, kid: 'key-1', use: 'sig' })).toThrow(
      `The jwks contains 2 keys with kid 'key-1' that differ`
    )
  })

  it('rejects the kid as ambiguous when the keys are the same key with a different alg', () => {
    const jwks = {
      keys: [
        { ...key, alg: 'ES256' },
        { ...key, alg: 'ECDH-ES' },
      ],
    }

    expect(() => extractJwkFromJwkSet({ jwks, kid: 'key-1', use: 'sig' })).toThrow(
      `The jwks contains 2 keys with kid 'key-1' that differ`
    )
  })

  it('counts every key with the kid when it is ambiguous', () => {
    expect(() => extractJwkFromJwkSet({ jwks: { keys: [key, key, otherKey] }, kid: 'key-1', use: 'sig' })).toThrow(
      `The jwks contains 3 keys with kid 'key-1' that differ`
    )
  })

  it('selects the key when the set lists it twice', () => {
    expect(extractJwkFromJwkSet({ jwks: { keys: [key, { ...key }] }, kid: 'key-1', use: 'sig' })).toEqual(key)
  })

  it('selects the key when the set lists it twice with its members in another order', () => {
    const reordered = { kid: 'key-1', y: 'eTE', x: 'eDE', crv: 'P-256', kty: 'EC' }

    expect(extractJwkFromJwkSet({ jwks: { keys: [key, reordered] }, kid: 'key-1', use: 'sig' })).toEqual(key)
  })

  it('selects the key for the use when the other key with the kid is for another use', () => {
    const jwks = {
      keys: [
        { ...otherKey, use: 'enc' },
        { ...key, use: 'sig' },
      ],
    }

    expect(extractJwkFromJwkSet({ jwks, kid: 'key-1', use: 'sig' })).toEqual({ ...key, use: 'sig' })
  })

  it('selects the only key for the use when no kid is given and the set lists it twice', () => {
    expect(extractJwkFromJwkSet({ jwks: { keys: [key, { ...key }] }, use: 'sig' })).toEqual(key)
  })

  it('rejects a missing kid as ambiguous when the keys for the use differ', () => {
    expect(() => extractJwkFromJwkSet({ jwks: { keys: [key, otherKey] }, use: 'sig' })).toThrow(
      expect.objectContaining({
        name: JoseSignerError.name,
        message: expect.stringContaining('No kid provided and the jwks contains 2 keys for this use.'),
      })
    )
  })
})
