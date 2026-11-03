import { afterEach, describe, expect, it, vi } from 'vitest'
import { JoseSignatureVerificationError } from '../error'
import { signJwt } from '../jwt/sign-jwt'
import { verifyJwt } from '../jwt/verify-jwt'
import { verifyJwtClaims } from '../jwt/verify-jwt-claims'
import { claimIssue, createEs256Context } from './context'

/**
 * The edges of the validity window, to the millisecond. They are the ones `@sd-jwt/core` applied
 * before it moved to `@owf/jose`: `exp` is exclusive and `nbf`, `iat` and the maximum age are
 * inclusive, each widened by the skew. `@openid4vc/oauth2` still accepted a token at exactly its
 * `exp`, which RFC 7519 does not allow.
 */

const now = new Date('2026-09-15T12:00:00Z')

/** The NumericDate `seconds` after `now`, which may be fractional or negative. */
const at = (seconds: number) => now.getTime() / 1000 + seconds

describe('exp', () => {
  it('rejects a token at exactly its exp when there is no clock skew', () => {
    expect(() => verifyJwtClaims({ exp: at(0) }, { now, skewSeconds: 0 })).toThrow(claimIssue('exp', 'expired'))
  })

  it('accepts a token one millisecond before its exp when there is no clock skew', () => {
    expect(() => verifyJwtClaims({ exp: at(0.001) }, { now, skewSeconds: 0 })).not.toThrow()
  })

  it('rejects a fractional exp that passed less than a second ago when there is no clock skew', () => {
    expect(() => verifyJwtClaims({ exp: at(-0.4) }, { now, skewSeconds: 0 })).toThrow(claimIssue('exp', 'expired'))
  })

  it('accepts a token whose exp passed 29 seconds ago under the default clock skew', () => {
    expect(() => verifyJwtClaims({ exp: at(-29) }, { now })).not.toThrow()
  })

  it('rejects a token whose exp passed exactly 30 seconds ago under the default clock skew', () => {
    expect(() => verifyJwtClaims({ exp: at(-30) }, { now })).toThrow(claimIssue('exp', 'expired'))
  })

  it('accepts a token whose exp passed within a configured clock skew', () => {
    expect(() => verifyJwtClaims({ exp: at(-119) }, { now, skewSeconds: 120 })).not.toThrow()
  })

  it('rejects a token whose exp passed exactly a configured clock skew ago', () => {
    expect(() => verifyJwtClaims({ exp: at(-120) }, { now, skewSeconds: 120 })).toThrow(claimIssue('exp', 'expired'))
  })

  it('accepts an expired token when checkExpirationTime is false', () => {
    expect(() => verifyJwtClaims({ exp: at(-3600) }, { now, checkExpirationTime: false })).not.toThrow()
  })

  it('still checks exp when checkNotBefore and checkIssuedAt are false', () => {
    expect(() => verifyJwtClaims({ exp: at(-3600) }, { now, checkNotBefore: false, checkIssuedAt: false })).toThrow(
      claimIssue('exp', 'expired')
    )
  })
})

describe('nbf', () => {
  it('accepts a token at exactly its nbf when there is no clock skew', () => {
    expect(() => verifyJwtClaims({ nbf: at(0) }, { now, skewSeconds: 0 })).not.toThrow()
  })

  it('rejects a token one millisecond before its nbf when there is no clock skew', () => {
    expect(() => verifyJwtClaims({ nbf: at(0.001) }, { now, skewSeconds: 0 })).toThrow(
      claimIssue('nbf', 'not_yet_valid')
    )
  })

  it('accepts a token whose nbf is 30 seconds away under the default clock skew', () => {
    expect(() => verifyJwtClaims({ nbf: at(30) }, { now })).not.toThrow()
  })

  it('rejects a token whose nbf is 31 seconds away under the default clock skew', () => {
    expect(() => verifyJwtClaims({ nbf: at(31) }, { now })).toThrow(claimIssue('nbf', 'not_yet_valid'))
  })

  it('accepts a token that is not valid yet when checkNotBefore is false', () => {
    expect(() => verifyJwtClaims({ nbf: at(3600) }, { now, checkNotBefore: false })).not.toThrow()
  })
})

describe('iat', () => {
  it('accepts a token issued at exactly now when there is no clock skew', () => {
    expect(() => verifyJwtClaims({ iat: at(0) }, { now, skewSeconds: 0 })).not.toThrow()
  })

  it('rejects a token issued one second in the future when there is no clock skew', () => {
    expect(() => verifyJwtClaims({ iat: at(1) }, { now, skewSeconds: 0 })).toThrow(claimIssue('iat', 'not_yet_valid'))
  })

  it('accepts a token issued 30 seconds in the future under the default clock skew', () => {
    expect(() => verifyJwtClaims({ iat: at(30) }, { now })).not.toThrow()
  })

  it('rejects a token issued 31 seconds in the future under the default clock skew', () => {
    expect(() => verifyJwtClaims({ iat: at(31) }, { now })).toThrow(claimIssue('iat', 'not_yet_valid'))
  })
})

describe('maxAgeSeconds', () => {
  it('accepts a token exactly maxAgeSeconds old when there is no clock skew', () => {
    expect(() => verifyJwtClaims({ iat: at(-60) }, { now, skewSeconds: 0, maxAgeSeconds: 60 })).not.toThrow()
  })

  it('rejects a token one millisecond older than maxAgeSeconds when there is no clock skew', () => {
    expect(() => verifyJwtClaims({ iat: at(-60.001) }, { now, skewSeconds: 0, maxAgeSeconds: 60 })).toThrow(
      claimIssue('iat', 'expired')
    )
  })

  it('accepts a token as old as maxAgeSeconds plus the default clock skew', () => {
    expect(() => verifyJwtClaims({ iat: at(-90) }, { now, maxAgeSeconds: 60 })).not.toThrow()
  })

  it('rejects a token a second older than maxAgeSeconds plus the default clock skew', () => {
    expect(() => verifyJwtClaims({ iat: at(-91) }, { now, maxAgeSeconds: 60 })).toThrow(claimIssue('iat', 'expired'))
  })

  it('still enforces maxAgeSeconds when checkIssuedAt is false', () => {
    expect(() => verifyJwtClaims({ iat: at(-91) }, { now, maxAgeSeconds: 60, checkIssuedAt: false })).toThrow(
      claimIssue('iat', 'expired')
    )
  })
})

describe('requiredClaims', () => {
  // `@openid4vc/oauth2` checked for a truthy value, so an empty string or 0 counted as missing there
  it.each([
    ['an empty string', ''],
    ['zero', 0],
    ['false', false],
    ['null', null],
  ])('counts a claim whose value is %s as present', (_description, value) => {
    expect(() => verifyJwtClaims({ claim: value }, { now, requiredClaims: ['claim'] })).not.toThrow()
  })

  it('reports every required claim that is missing', () => {
    const verify = () =>
      verifyJwtClaims({ iss: 'https://issuer.example' }, { now, requiredClaims: ['iss', 'sub', 'aud'] })

    expect(verify).toThrow(claimIssue('sub', 'claim_missing'))
    expect(verify).toThrow(claimIssue('aud', 'claim_missing'))
  })

  it('requires no claim when no requiredClaims are given, not even exp', () => {
    expect(() => verifyJwtClaims({}, { now })).not.toThrow()
  })
})

describe('expected values', () => {
  const options = {
    iss: (value: string | string[]) => ({ expectedIssuer: value }),
    sub: (value: string | string[]) => ({ expectedSubject: value }),
    nonce: (value: string) => ({ expectedNonce: value }),
  }

  it.each(['iss', 'sub', 'nonce'] as const)('rejects a token without %s when a value is expected', (claim) => {
    expect(() => verifyJwtClaims({}, { now, ...options[claim]('expected') })).toThrow(
      claimIssue(claim, 'claim_missing')
    )
  })

  it.each(['iss', 'sub', 'nonce'] as const)('rejects a token whose %s is not the expected value', (claim) => {
    expect(() => verifyJwtClaims({ [claim]: 'other' }, { now, ...options[claim]('expected') })).toThrow(
      claimIssue(claim, 'claim_value_mismatch')
    )
  })

  it.each(['iss', 'sub', 'nonce'] as const)('compares %s case-sensitively', (claim) => {
    expect(() =>
      verifyJwtClaims({ [claim]: 'https://Example.com' }, { now, ...options[claim]('https://example.com') })
    ).toThrow(claimIssue(claim, 'claim_value_mismatch'))
  })

  it('accepts an iss that is one of several expected issuers', () => {
    expect(() =>
      verifyJwtClaims({ iss: 'https://b.example' }, { now, expectedIssuer: ['https://a.example', 'https://b.example'] })
    ).not.toThrow()
  })

  it('rejects every iss when the expected issuers are an empty list', () => {
    expect(() => verifyJwtClaims({ iss: 'https://a.example' }, { now, expectedIssuer: [] })).toThrow(
      claimIssue('iss', 'claim_value_mismatch')
    )
  })

  it('rejects an iss that is not a string, which only an unvalidated payload can carry', () => {
    const iss = 1 as unknown as string

    expect(() => verifyJwtClaims({ iss }, { now, expectedIssuer: '1' })).toThrow(
      claimIssue('iss', 'claim_value_mismatch')
    )
  })

  it('checks an empty expected nonce rather than skipping it', () => {
    // `@openid4vc/oauth2` skipped the check for an empty expected value
    expect(() => verifyJwtClaims({}, { now, expectedNonce: '' })).toThrow(claimIssue('nonce', 'claim_missing'))
  })

  it('accepts a string aud that is one of several expected audiences', () => {
    expect(() =>
      verifyJwtClaims(
        { aud: 'https://b.example' },
        { now, expectedAudience: ['https://a.example', 'https://b.example'] }
      )
    ).not.toThrow()
  })

  it('accepts an aud array that shares one audience with several expected audiences', () => {
    expect(() =>
      verifyJwtClaims(
        { aud: ['https://x.example', 'https://b.example'] },
        { now, expectedAudience: ['https://a.example', 'https://b.example'] }
      )
    ).not.toThrow()
  })

  it('rejects an empty aud array', () => {
    expect(() => verifyJwtClaims({ aud: [] }, { now, expectedAudience: 'https://a.example' })).toThrow(
      claimIssue('aud', 'claim_value_mismatch')
    )
  })

  it('rejects a token without aud when an audience is expected', () => {
    expect(() => verifyJwtClaims({}, { now, expectedAudience: 'https://a.example' })).toThrow(
      claimIssue('aud', 'claim_missing')
    )
  })
})

describe('the options verifyJwtClaims falls back on', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('uses the current time when now is not given', () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2100-01-01T00:00:00Z'))

    // Valid for decades by the actual clock, so only the current time as the system reports it
    // can make it expired
    const exp = new Date('2099-01-01T00:00:00Z').getTime() / 1000

    expect(() => verifyJwtClaims({ exp })).toThrow(claimIssue('exp', 'expired'))
  })

  it('starts the error with the given errorMessage', () => {
    expect(() =>
      verifyJwtClaims({ exp: at(-3600) }, { now, errorMessage: 'Unable to verify the key binding JWT.' })
    ).toThrow(
      expect.objectContaining({
        message: expect.stringMatching(/^Unable to verify the key binding JWT\.\n {2}- exp: /),
      })
    )
  })
})

describe('verifyJwt', () => {
  const signedJwt = async (payload: Record<string, unknown>) => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()
    const { jwt } = await signJwt({
      payload,
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
    })

    return { jwt, verifyJws }
  }

  it('accepts a token that expired 10 seconds ago with the default clock skew', async () => {
    const { jwt, verifyJws } = await signedJwt({ iss: 'https://issuer.example', exp: at(-10) })

    const { payload } = await verifyJwt({ jwt, verifyJwsCallback: verifyJws, now })

    expect(payload).toEqual({ iss: 'https://issuer.example', exp: at(-10) })
  })

  it('rejects a token that expired 31 seconds ago with the default clock skew', async () => {
    const { jwt, verifyJws } = await signedJwt({ exp: at(-31) })

    await expect(verifyJwt({ jwt, verifyJwsCallback: verifyJws, now })).rejects.toThrow(claimIssue('exp', 'expired'))
  })

  it('rejects a token whose aud is not the expected one', async () => {
    const { jwt, verifyJws } = await signedJwt({ aud: 'https://other.example' })

    await expect(
      verifyJwt({ jwt, verifyJwsCallback: verifyJws, now, expectedAudience: 'https://verifier.example' })
    ).rejects.toThrow(claimIssue('aud', 'claim_value_mismatch'))
  })

  it('starts a claim error with the errorMessage given to verifyJwt', async () => {
    const { jwt, verifyJws } = await signedJwt({ exp: at(-3600) })

    await expect(
      verifyJwt({ jwt, verifyJwsCallback: verifyJws, now, errorMessage: 'Unable to verify the DPoP proof.' })
    ).rejects.toThrow(
      expect.objectContaining({ message: expect.stringMatching(/^Unable to verify the DPoP proof\.\n {2}- exp: /) })
    )
  })

  it('uses the errorMessage given to verifyJwt for a signature that does not verify', async () => {
    const { jwt } = await signedJwt({ iss: 'https://issuer.example' })
    const { verifyJws: verifyWithAnotherKey } = await createEs256Context()

    await expect(
      verifyJwt({ jwt, verifyJwsCallback: verifyWithAnotherKey, now, errorMessage: 'Unable to verify the DPoP proof.' })
    ).rejects.toThrow(
      expect.objectContaining({
        name: JoseSignatureVerificationError.name,
        message: 'Unable to verify the DPoP proof.',
      })
    )
  })
})
