import { base64url, type HashAlgorithm, type Hasher, stringToBytes } from '@owf/identity-common'
import * as referenceJose from 'jose'
import { describe, expect, it } from 'vitest'
import { JoseValidationError } from '../error'
import { isJwkInSet } from '../jwk/jwks'
import { calculateJwkThumbprint, calculateJwkThumbprintUri } from '../jwk/thumbprint'
import type { Jwk } from '../jwk/z-jwk'

/** Matches a thrown error by its class and a part of its message. */
const joseError = (type: { name: string }, message: string) =>
  expect.objectContaining({ name: type.name, message: expect.stringContaining(message) })

const hashCallback: Hasher = async (data, alg) =>
  new Uint8Array(
    await globalThis.crypto.subtle.digest(alg.toUpperCase(), typeof data === 'string' ? stringToBytes(data) : data)
  )

/**
 * The thumbprint of the JSON object written out in `canonicalJson`, computed without this package:
 * what the thumbprint of a key has to be when `canonicalJson` is the canonical form RFC 7638 gives it.
 */
const thumbprintOf = async (canonicalJson: string, hashAlgorithm: HashAlgorithm = 'sha-256') =>
  base64url.encode(await hashCallback(canonicalJson, hashAlgorithm))

const thumbprint = (jwk: Jwk, hashAlgorithm: HashAlgorithm = 'sha-256') =>
  calculateJwkThumbprint({ jwk, hashAlgorithm, hashCallback })

// The key of RFC 7638 section 3.1
const rsaModulus =
  '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw'
const rsaThumbprint = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'

// The keys of RFC 8037 Appendix A.1 and A.2, and their thumbprint from A.3
const ed25519PublicJwk = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }
const ed25519PrivateJwk = { ...ed25519PublicJwk, d: 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A' }
const ed25519Thumbprint = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k'

// The EC public key of RFC 7517 Appendix A.1
const ecX = 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4'
const ecY = '4Etl6SRW2YilurN5ZTeEO8-AP1kZDMH3eI5_y5yWEyM'
const ecJwk = { kty: 'EC', crv: 'P-256', x: ecX, y: ecY, use: 'enc', kid: '1' }

// A symmetric key of RFC 7517 Appendix A.3
const octJwk = { kty: 'oct', alg: 'A128KW', k: 'GawgguFyGrWKav7AX4VKUg' }

describe('calculateJwkThumbprint', () => {
  it('matches the RFC 7638 example for the members of the RSA key in another order', async () => {
    expect(await thumbprint({ n: rsaModulus, kid: '2011-04-29', e: 'AQAB', alg: 'RS256', kty: 'RSA' })).toBe(
      rsaThumbprint
    )
  })

  it('gives an RSA private key the thumbprint of its public key', async () => {
    const privateMembers = { d: 'ZA', p: 'cA', q: 'cQ', dp: 'ZHA', dq: 'ZHE', qi: 'cWk' }

    expect(await thumbprint({ kty: 'RSA', n: rsaModulus, e: 'AQAB', ...privateMembers })).toBe(rsaThumbprint)
  })

  it('matches the RFC 8037 example for an Ed25519 public key', async () => {
    expect(await thumbprint(ed25519PublicJwk)).toBe(ed25519Thumbprint)
  })

  it('gives the Ed25519 private key of RFC 8037 the thumbprint of its public key', async () => {
    expect(await thumbprint(ed25519PrivateJwk)).toBe(ed25519Thumbprint)
  })

  it('hashes exactly crv, kty, x and y of an EC key, in that order', async () => {
    const reordered = { y: ecY, use: 'enc', x: ecX, key_ops: ['verify'], kty: 'EC', ext: true, crv: 'P-256', kid: '1' }

    expect(await thumbprint(reordered)).toBe(await thumbprintOf(`{"crv":"P-256","kty":"EC","x":"${ecX}","y":"${ecY}"}`))
  })

  it('hashes exactly k and kty of a symmetric key', async () => {
    expect(await thumbprint(octJwk)).toBe(await thumbprintOf('{"k":"GawgguFyGrWKav7AX4VKUg","kty":"oct"}'))
  })

  it.each(['sha-384', 'sha-512'] as const)('computes the thumbprint with %s when asked to', async (hash) => {
    expect(await thumbprint(ecJwk, hash)).toBe(
      await thumbprintOf(`{"crv":"P-256","kty":"EC","x":"${ecX}","y":"${ecY}"}`, hash)
    )
  })

  it.each([
    ['EC', ecJwk],
    ['OKP', ed25519PublicJwk],
    ['RSA', { kty: 'RSA', n: rsaModulus, e: 'AQAB' }],
    ['oct', octJwk],
  ])('agrees with an independent JOSE implementation for an %s key', async (_kty, jwk) => {
    expect(await thumbprint(jwk)).toBe(await referenceJose.calculateJwkThumbprint(jwk as referenceJose.JWK, 'sha256'))
  })

  it('rejects a key type for which no thumbprint members are defined', async () => {
    // An ML-DSA key, whose key type this package does not know
    await expect(thumbprint({ kty: 'AKP', alg: 'ML-DSA-44', pub: 'cHVibGlj' })).rejects.toThrow(
      joseError(JoseValidationError, 'Unable to calculate the thumbprint of the jwk')
    )
  })

  it('rejects an OKP key without x', async () => {
    await expect(thumbprint({ kty: 'OKP', crv: 'Ed25519' })).rejects.toThrow(
      joseError(JoseValidationError, 'Unable to calculate the thumbprint of the jwk')
    )
  })

  it('rejects an EC key whose x is not a string', async () => {
    const jwk = { kty: 'EC', crv: 'P-256', x: 1, y: ecY } as unknown as Jwk

    await expect(thumbprint(jwk)).rejects.toThrow(
      joseError(JoseValidationError, 'Unable to calculate the thumbprint of the jwk')
    )
  })
})

describe('calculateJwkThumbprintUri', () => {
  it('names the hash algorithm in the URI', async () => {
    const uri = await calculateJwkThumbprintUri({ jwk: ecJwk, hashAlgorithm: 'sha-512', hashCallback })

    expect(uri).toBe(
      `urn:ietf:params:oauth:jwk-thumbprint:sha-512:${await thumbprintOf(`{"crv":"P-256","kty":"EC","x":"${ecX}","y":"${ecY}"}`, 'sha-512')}`
    )
  })
})

describe('isJwkInSet', () => {
  it('finds a key in a set of keys of different types', async () => {
    const jwks = [ecJwk, ed25519PublicJwk, { kty: 'RSA', n: rsaModulus, e: 'AQAB', kid: '2011-04-29' }]

    expect(await isJwkInSet({ jwk: { kty: 'RSA', n: rsaModulus, e: 'AQAB' }, jwks, hashCallback })).toBe(true)
  })

  it('finds a public key in a set holding its private key', async () => {
    expect(await isJwkInSet({ jwk: ed25519PublicJwk, jwks: [ed25519PrivateJwk], hashCallback })).toBe(true)
  })

  it('does not find a key that only shares its x with a key in the set', async () => {
    expect(await isJwkInSet({ jwk: { ...ecJwk, y: ecX }, jwks: [ecJwk], hashCallback })).toBe(false)
  })

  it('does not find a key on another curve with the same coordinates', async () => {
    expect(await isJwkInSet({ jwk: { ...ecJwk, crv: 'P-384' }, jwks: [ecJwk], hashCallback })).toBe(false)
  })

  it('does not find a key in an empty set', async () => {
    expect(await isJwkInSet({ jwk: ecJwk, jwks: [], hashCallback })).toBe(false)
  })
})

/**
 * A key in the set whose thumbprint cannot be computed cannot be the key looked for, whose thumbprint
 * can. Whether the key is found must not depend on whether such a key comes before or after it.
 */
describe('isJwkInSet with a set that holds a key without a thumbprint', () => {
  // An ML-DSA key: RFC 7638 names no thumbprint members for its key type
  const mlDsaJwk = { kty: 'AKP', alg: 'ML-DSA-44', pub: 'cHVibGlj' }

  it('finds a key that comes after a key type without thumbprint members', async () => {
    expect(await isJwkInSet({ jwk: ecJwk, jwks: [mlDsaJwk, ecJwk], hashCallback })).toBe(true)
  })

  it('finds a key that comes before a key type without thumbprint members', async () => {
    expect(await isJwkInSet({ jwk: ecJwk, jwks: [ecJwk, mlDsaJwk], hashCallback })).toBe(true)
  })

  it('does not find a key in a set that only holds a key type without thumbprint members', async () => {
    expect(await isJwkInSet({ jwk: ecJwk, jwks: [mlDsaJwk], hashCallback })).toBe(false)
  })

  it('finds a key that comes after a key missing a member the thumbprint is computed over', async () => {
    const { y: _y, ...withoutY } = ecJwk

    expect(await isJwkInSet({ jwk: ecJwk, jwks: [withoutY, ecJwk], hashCallback })).toBe(true)
  })

  it('rejects a key to look for whose key type has no thumbprint members, whatever the set holds', async () => {
    await expect(isJwkInSet({ jwk: mlDsaJwk, jwks: [mlDsaJwk], hashCallback })).rejects.toThrow(
      joseError(JoseValidationError, 'Unable to calculate the thumbprint of the jwk')
    )
  })
})
