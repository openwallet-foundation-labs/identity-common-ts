import { describe, expect, it } from 'vitest'
import type { VerifyJwsCallback } from '../callbacks'
import { JoseSignerError, JoseValidationError } from '../error'
import { extractJwkFromJwkSet } from '../jwk/jwks'
import { parseJws } from '../jws/parse-jws'
import { jwsSignerFromHeader } from '../jws/signer'
import { verifyJwsSignature } from '../jws/verify-jws'
import { verifyJwt } from '../jwt/verify-jwt'
import { certificateChain } from './certificates'
import { unsignedCompactJws } from './context'

/** Matches a thrown error by its class and a part of its message. */
const joseError = (type: { name: string }, message: string) =>
  expect.objectContaining({ name: type.name, message: expect.stringContaining(message) })

const publicJwk = { kty: 'EC', crv: 'P-256', x: 'eA', y: 'eQ' }
const x5c = certificateChain
const trustChain: [string] = ['eyJhbGciOiJFUzI1NiJ9.e30.c2ln']
const did = 'did:example:123'

/**
 * A callback that accepts every signature, reporting `publicJwk` as the key: these tests are about
 * which signer is established, not about the signature.
 */
const acceptingCallback: VerifyJwsCallback = () => ({ verified: true, signerJwk: publicJwk })

describe('jwsSignerFromHeader', () => {
  describe('a header that identifies the signer in one way', () => {
    it('establishes an x5c signer that carries the kid of the header', () => {
      expect(jwsSignerFromHeader({ header: { alg: 'ES256', x5c, kid: 'key-1' } })).toEqual({
        method: 'x5c',
        alg: 'ES256',
        x5c,
        kid: 'key-1',
      })
    })

    it('establishes a jwk signer from the jwk header parameter', () => {
      expect(jwsSignerFromHeader({ header: { alg: 'ES256', jwk: publicJwk } })).toEqual({
        method: 'jwk',
        alg: 'ES256',
        publicJwk,
      })
    })

    it('establishes a federation signer from trust_chain and kid', () => {
      expect(jwsSignerFromHeader({ header: { alg: 'ES256', trust_chain: trustChain, kid: 'key-1' } })).toEqual({
        method: 'federation',
        alg: 'ES256',
        trustChain,
        kid: 'key-1',
      })
    })

    it('treats a fragment kid as a custom key id when there is no iss', () => {
      expect(jwsSignerFromHeader({ header: { alg: 'ES256', kid: '#key-1' } })).toEqual({
        method: 'custom',
        alg: 'ES256',
        kid: '#key-1',
      })
    })

    it('treats a fragment kid as a custom key id when iss is not a did', () => {
      expect(
        jwsSignerFromHeader({ header: { alg: 'ES256', kid: '#key-1' }, issuer: 'https://issuer.example' })
      ).toEqual({ method: 'custom', alg: 'ES256', kid: '#key-1' })
    })
  })

  describe('a header that identifies the signer in an invalid way', () => {
    it('rejects trust_chain without kid', () => {
      expect(() => jwsSignerFromHeader({ header: { alg: 'ES256', trust_chain: trustChain } })).toThrow(
        joseError(
          JoseSignerError,
          `FAILED: method federation - When 'trust_chain' is used in the header, the 'kid' parameter is required.`
        )
      )
    })

    it('rejects a did in iss when the header has no kid', () => {
      expect(() => jwsSignerFromHeader({ header: { alg: 'ES256' }, issuer: did })).toThrow(
        joseError(
          JoseSignerError,
          `FAILED: method did - kid in header must start with either 'did:' or '#' when the 'iss' value is a did`
        )
      )
    })
  })

  describe('a header that identifies the signer in several ways', () => {
    const allFourWays = { alg: 'ES256', x5c, trust_chain: trustChain, kid: `${did}#key-1`, jwk: publicJwk }

    it('rejects an x5c next to a did URL in kid', () => {
      expect(() => jwsSignerFromHeader({ header: { alg: 'ES256', x5c, kid: `${did}#key-1` } })).toThrow(
        joseError(JoseSignerError, `identifies the signer in 2 ways ('x5c', 'did')`)
      )
    })

    it('rejects an x5c next to a fragment kid that is resolved against the did in iss', () => {
      expect(() => jwsSignerFromHeader({ header: { alg: 'ES256', x5c, kid: '#key-1' }, issuer: did })).toThrow(
        joseError(JoseSignerError, `identifies the signer in 2 ways ('x5c', 'did')`)
      )
    })

    it('rejects a trust_chain whose kid is a did URL', () => {
      expect(() =>
        jwsSignerFromHeader({ header: { alg: 'ES256', trust_chain: trustChain, kid: `${did}#key-1` } })
      ).toThrow(joseError(JoseSignerError, `identifies the signer in 2 ways ('federation', 'did')`))
    })

    it('rejects a did URL in kid next to a jwk', () => {
      expect(() => jwsSignerFromHeader({ header: { alg: 'ES256', kid: `${did}#key-1`, jwk: publicJwk } })).toThrow(
        joseError(JoseSignerError, `identifies the signer in 2 ways ('did', 'jwk')`)
      )
    })

    it('rejects a header that identifies the signer in all four ways', () => {
      expect(() => jwsSignerFromHeader({ header: allFourWays })).toThrow(
        joseError(JoseSignerError, `identifies the signer in 4 ways ('x5c', 'federation', 'did', 'jwk')`)
      )
    })

    it('resolves to x5c first when several ways are allowed', () => {
      expect(jwsSignerFromHeader({ header: allFourWays, allowMultipleSignerMethods: true })).toEqual({
        method: 'x5c',
        alg: 'ES256',
        x5c,
        kid: `${did}#key-1`,
      })
    })

    it('resolves to federation before did and jwk when several ways are allowed', () => {
      const { x5c: _x5c, ...withoutX5c } = allFourWays

      expect(jwsSignerFromHeader({ header: withoutX5c, allowMultipleSignerMethods: true })).toEqual({
        method: 'federation',
        alg: 'ES256',
        trustChain,
        kid: `${did}#key-1`,
      })
    })

    it('resolves to did before jwk when several ways are allowed', () => {
      expect(
        jwsSignerFromHeader({
          header: { alg: 'ES256', kid: `${did}#key-1`, jwk: publicJwk },
          allowMultipleSignerMethods: true,
        })
      ).toEqual({ method: 'did', alg: 'ES256', didUrl: `${did}#key-1` })
    })

    it('establishes the one valid way when another way is configured invalidly', () => {
      // The did configuration is invalid (a did in iss, but a kid that is neither a did URL nor a
      // fragment), which leaves the x5c as the only way the signer is identified
      expect(jwsSignerFromHeader({ header: { alg: 'ES256', x5c, kid: 'key-1' }, issuer: did })).toEqual({
        method: 'x5c',
        alg: 'ES256',
        x5c,
        kid: 'key-1',
      })
    })
  })

  describe('allowedSignerMethods', () => {
    it('establishes the allowed way when the header identifies the signer in several ways', () => {
      expect(
        jwsSignerFromHeader({ header: { alg: 'ES256', x5c, jwk: publicJwk }, allowedSignerMethods: ['jwk'] })
      ).toEqual({ method: 'jwk', alg: 'ES256', publicJwk })
    })

    it('rejects a header whose only way is not allowed rather than falling back to a custom signer', () => {
      expect(() => jwsSignerFromHeader({ header: { alg: 'ES256', x5c }, allowedSignerMethods: ['custom'] })).toThrow(
        joseError(JoseSignerError, `Found 1 signer method(s) that are not allowed:\nSUCCEEDED: method x5c`)
      )
    })

    it('reports the invalid configuration of an allowed way', () => {
      expect(() =>
        jwsSignerFromHeader({ header: { alg: 'ES256', kid: 'key-1' }, issuer: did, allowedSignerMethods: ['did'] })
      ).toThrow(
        joseError(JoseSignerError, 'Found 1 allowed signer method(s), but they contained an invalid configuration')
      )
    })

    it('establishes a custom signer when custom is allowed and the header identifies no other way', () => {
      expect(jwsSignerFromHeader({ header: { alg: 'ES256', kid: 'key-1' }, allowedSignerMethods: ['custom'] })).toEqual(
        {
          method: 'custom',
          alg: 'ES256',
          kid: 'key-1',
        }
      )
    })

    it('rejects a header that identifies no signer when custom is not among the allowed ways', () => {
      expect(() =>
        jwsSignerFromHeader({ header: { alg: 'ES256', kid: 'key-1' }, allowedSignerMethods: ['x5c', 'jwk'] })
      ).toThrow(
        joseError(
          JoseSignerError,
          `The header identifies no signer method, and the 'custom' signer method is not allowed.`
        )
      )
    })
  })
})

describe('a jwk header parameter carrying private key material', () => {
  it('is rejected for a symmetric key', () => {
    const jws = unsignedCompactJws({ alg: 'HS256', jwk: { kty: 'oct', k: 'c2VjcmV0' } }, {})

    expect(() => parseJws({ jws })).toThrow(joseError(JoseValidationError, `contains the private key member(s) 'k'`))
  })

  it('is rejected naming every private member of an RSA key', () => {
    const rsaPrivateJwk = { kty: 'RSA', n: 'bg', e: 'AQAB', d: 'ZA', p: 'cA', q: 'cQ', dp: 'ZHA', dq: 'ZHE', qi: 'cWk' }
    const jws = unsignedCompactJws({ alg: 'RS256', jwk: rsaPrivateJwk }, {})

    expect(() => parseJws({ jws })).toThrow(
      joseError(JoseValidationError, `contains the private key member(s) 'd', 'p', 'q', 'dp', 'dq', 'qi'`)
    )
  })

  it('never reaches the verification callback', async () => {
    let callbackCalled = false
    const jwt = unsignedCompactJws({ alg: 'ES256', jwk: { ...publicJwk, d: 'ZA' } }, { iss: 'https://issuer.example' })

    await expect(
      verifyJwt({
        jwt,
        verifyJwsCallback: () => {
          callbackCalled = true
          return { verified: true, signerJwk: publicJwk }
        },
      })
    ).rejects.toThrow(joseError(JoseValidationError, `contains the private key member(s) 'd'`))
    expect(callbackCalled).toBe(false)
  })
})

describe('the signer verification establishes', () => {
  it('is the signer established from the header, with the key the callback verified with', async () => {
    const jws = parseJws({ jws: unsignedCompactJws({ alg: 'ES256', x5c }, {}) })

    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: acceptingCallback })

    expect(signer).toEqual({ method: 'x5c', alg: 'ES256', x5c, kid: undefined, publicJwk })
  })

  it('is the signer the caller passes, without the header being resolved at all', async () => {
    // Ambiguous as a header, but the caller already knows who signed
    const jws = parseJws({ jws: unsignedCompactJws({ alg: 'ES256', x5c, jwk: publicJwk }, {}) })

    const { signer } = await verifyJwsSignature({
      jws,
      signer: { method: 'did', alg: 'ES256', didUrl: `${did}#key-1` },
      verifyJwsCallback: acceptingCallback,
    })

    expect(signer).toEqual({ method: 'did', alg: 'ES256', didUrl: `${did}#key-1`, publicJwk })
  })

  it('resolves a fragment kid against the iss of the JWT', async () => {
    const jwt = unsignedCompactJws({ alg: 'ES256', kid: '#key-1' }, { iss: did })

    const { signer } = await verifyJwt({ jwt, verifyJwsCallback: acceptingCallback })

    expect(signer).toEqual({ method: 'did', alg: 'ES256', didUrl: `${did}#key-1`, publicJwk })
  })

  it('rejects a did URL in kid that belongs to another did than the iss of the JWT', async () => {
    const jwt = unsignedCompactJws({ alg: 'ES256', kid: 'did:example:456#key-1' }, { iss: did })

    await expect(verifyJwt({ jwt, verifyJwsCallback: acceptingCallback })).rejects.toThrow(
      joseError(JoseSignerError, 'FAILED: method did')
    )
  })

  it('accepts a did URL in kid with an iss that is not a did when verifyJwt allows the mismatch', async () => {
    // As for an `openid4vci-proof+jwt`, whose `iss` is the client id
    const jwt = unsignedCompactJws({ alg: 'ES256', kid: `${did}#key-1` }, { iss: 'client-id' })

    const { signer } = await verifyJwt({ jwt, verifyJwsCallback: acceptingCallback, allowDidKidIssuerMismatch: true })

    expect(signer).toEqual({ method: 'did', alg: 'ES256', didUrl: `${did}#key-1`, publicJwk })
  })

  it('surfaces a header that identifies the signer in several ways as a JoseSignerError through verifyJwt', async () => {
    const jwt = unsignedCompactJws({ alg: 'ES256', x5c, jwk: publicJwk }, {})

    await expect(verifyJwt({ jwt, verifyJwsCallback: acceptingCallback })).rejects.toThrow(
      joseError(JoseSignerError, `identifies the signer in 2 ways ('x5c', 'jwk')`)
    )
  })

  it('is narrowed down by the allowedSignerMethods given to verifyJwt', async () => {
    const jwt = unsignedCompactJws({ alg: 'ES256', x5c, jwk: publicJwk }, {})

    const { signer } = await verifyJwt({ jwt, verifyJwsCallback: acceptingCallback, allowedSignerMethods: ['jwk'] })

    expect(signer).toEqual({ method: 'jwk', alg: 'ES256', publicJwk })
  })

  it('ignores a jwk in the unprotected header, which is not integrity protected', async () => {
    const jws = parseJws({
      jws: {
        protected: unsignedCompactJws({ alg: 'ES256' }, {}).split('.')[0],
        header: { jwk: publicJwk },
        payload: 'e30',
        signature: 'c2ln',
      },
    })

    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: acceptingCallback })

    expect(signer).toEqual({ method: 'custom', alg: 'ES256', kid: undefined, publicJwk })
  })

  it('ignores a kid in the unprotected header, which is not integrity protected', async () => {
    const jws = parseJws({
      jws: {
        protected: unsignedCompactJws({ alg: 'ES256' }, {}).split('.')[0],
        header: { kid: `${did}#key-1` },
        payload: 'e30',
        signature: 'c2ln',
      },
    })

    const { signer } = await verifyJwsSignature({ jws, verifyJwsCallback: acceptingCallback })

    expect(signer).toEqual({ method: 'custom', alg: 'ES256', kid: undefined, publicJwk })
  })
})

describe('extractJwkFromJwkSet', () => {
  const keyWithoutUse = { ...publicJwk, kid: 'key-1' }
  const encryptionKey = { ...publicJwk, kid: 'key-2', use: 'enc' }

  it('selects a key that declares no use for signature verification', () => {
    expect(extractJwkFromJwkSet({ jwks: { keys: [keyWithoutUse, encryptionKey] }, kid: 'key-1', use: 'sig' })).toEqual(
      keyWithoutUse
    )
  })

  it('does not select an encryption key by its kid for signature verification', () => {
    expect(() => extractJwkFromJwkSet({ jwks: { keys: [encryptionKey] }, kid: 'key-2', use: 'sig' })).toThrow(
      joseError(JoseSignerError, `Unable to extract jwk from jwks for use 'sig'. No key with kid 'key-2' found.`)
    )
  })

  it('rejects a kid that is not in a set holding a single key rather than returning that key', () => {
    // `@openid4vc/oauth2` returned the only key of the set here, whatever the kid said
    expect(() => extractJwkFromJwkSet({ jwks: { keys: [keyWithoutUse] }, kid: 'key-3', use: 'sig' })).toThrow(
      joseError(JoseSignerError, `No key with kid 'key-3' found.`)
    )
  })

  it('rejects an empty set', () => {
    expect(() => extractJwkFromJwkSet({ jwks: { keys: [] }, use: 'sig' })).toThrow(
      joseError(JoseSignerError, `No kid provided and the jwks contains 0 keys for this use.`)
    )
  })
})
