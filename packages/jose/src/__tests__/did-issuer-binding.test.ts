import { describe, expect, it } from 'vitest'
import { JoseSignerError } from '../error'
import { jwsSignerFromHeader } from '../jws/signer'
import { verifyJwt } from '../jwt/verify-jwt'
import { unsignedCompactJws } from './context'

const mismatch = `kid in header starts with a did that is different from the did value in 'iss'`

/**
 * A DID in `kid` is only bound to the issuer when it is the DID in `iss`: a DID that merely starts
 * with the issuer's DID is a different DID, controlled by somebody else.
 */
describe('binding a did kid to the iss', () => {
  it('rejects a kid whose did extends the host of the iss did', () => {
    expect(() =>
      jwsSignerFromHeader({
        header: { alg: 'ES256', kid: 'did:web:example.com.evil.org#key-1' },
        issuer: 'did:web:example.com',
      })
    ).toThrow(mismatch)
  })

  it('rejects a kid whose did adds a path segment to the iss did', () => {
    expect(() =>
      jwsSignerFromHeader({
        header: { alg: 'ES256', kid: 'did:web:example.com:evil#key-1' },
        issuer: 'did:web:example.com',
      })
    ).toThrow(mismatch)
  })

  it('rejects a kid whose did extends the last segment of the iss did', () => {
    expect(() =>
      jwsSignerFromHeader({
        header: { alg: 'ES256', kid: 'did:web:host:tenant2#key-1' },
        issuer: 'did:web:host:tenant',
      })
    ).toThrow(mismatch)
  })

  it('rejects a did kid when iss is not a did', () => {
    expect(() =>
      jwsSignerFromHeader({ header: { alg: 'ES256', kid: 'did:web:example.com#key-1' }, issuer: 'https://example.com' })
    ).toThrow(mismatch)
  })

  it('accepts a kid that is the iss did followed by a fragment', () => {
    expect(
      jwsSignerFromHeader({ header: { alg: 'ES256', kid: 'did:web:example.com#key-1' }, issuer: 'did:web:example.com' })
    ).toEqual({ method: 'did', alg: 'ES256', didUrl: 'did:web:example.com#key-1' })
  })

  it('accepts a kid that is the iss did followed by a path and a query', () => {
    expect(
      jwsSignerFromHeader({
        header: { alg: 'ES256', kid: 'did:example:123/keys?versionId=1#key-1' },
        issuer: 'did:example:123',
      })
    ).toEqual({ method: 'did', alg: 'ES256', didUrl: 'did:example:123/keys?versionId=1#key-1' })
  })

  it('accepts a kid that is exactly the iss did', () => {
    expect(
      jwsSignerFromHeader({ header: { alg: 'ES256', kid: 'did:example:123' }, issuer: 'did:example:123' })
    ).toEqual({
      method: 'did',
      alg: 'ES256',
      didUrl: 'did:example:123',
    })
  })

  it('accepts a kid whose did extends the iss did when the caller allows a mismatch', () => {
    expect(
      jwsSignerFromHeader({
        header: { alg: 'ES256', kid: 'did:web:example.com.evil.org#key-1' },
        issuer: 'did:web:example.com',
        allowDidKidIssuerMismatch: true,
      })
    ).toEqual({ method: 'did', alg: 'ES256', didUrl: 'did:web:example.com.evil.org#key-1' })
  })

  it('rejects a JWT signed by a did that extends its iss before the verification callback is called', async () => {
    const jwt = unsignedCompactJws(
      { alg: 'ES256', kid: 'did:web:example.com.evil.org#key-1' },
      { iss: 'did:web:example.com' }
    )
    let calls = 0

    await expect(
      verifyJwt({
        jwt,
        verifyJwsCallback: () => {
          calls++
          return { verified: true, signerJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } }
        },
      })
    ).rejects.toThrow(JoseSignerError)
    expect(calls).toBe(0)
  })
})
