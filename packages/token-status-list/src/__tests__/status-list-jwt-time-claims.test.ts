import { JoseClaimVerificationError } from '@owf/jose'
import { describe, expect, it } from 'vitest'
import { type VerifyStatusListJwtOptions, verifyStatusListJwt } from '../status-list-jwt'
import { verifyJws } from './context'
import { now, secondsFromNow, signStatusListToken, uri } from './status-list-jwt-tokens'

// The time claims of a signed Status List Token, verified through `verifyStatusListJwt` at `now`.
// Unless a test says otherwise, the clock skew is the default of 30 seconds.

const verify = async (
  claims: Record<string, unknown>,
  options: Partial<Omit<VerifyStatusListJwtOptions, 'jwt'>> = {}
) => verifyStatusListJwt({ jwt: await signStatusListToken(claims), uri, now, verifyJwsCallback: verifyJws, ...options })

const expectRejectedClaim = async (verification: Promise<unknown>, claim: string, reason: string) => {
  await expect(verification).rejects.toThrow(JoseClaimVerificationError)
  await expect(verification).rejects.toMatchObject({ claim, reason })
}

describe('iat', () => {
  it('accepts a token issued 30 seconds after now, within the default skew', async () => {
    const { payload } = await verify({ iat: secondsFromNow(30) })

    expect(payload.iat).toBe(secondsFromNow(30))
  })

  it('rejects a token issued more than 30 seconds after now', async () => {
    await expectRejectedClaim(verify({ iat: secondsFromNow(31) }), 'iat', 'not-yet-valid')
  })

  it('rejects a token issued a second after now when there is no skew', async () => {
    await expectRejectedClaim(verify({ iat: secondsFromNow(1) }, { skewSeconds: 0 }), 'iat', 'not-yet-valid')
  })

  it('does not compare iat with now when checkIssuedAt is false', async () => {
    const { payload } = await verify({ iat: secondsFromNow(3600) }, { checkIssuedAt: false })

    expect(payload.iat).toBe(secondsFromNow(3600))
  })

  it('rejects a token older than maxAgeSeconds', async () => {
    await expectRejectedClaim(verify({ iat: secondsFromNow(-3600) }, { maxAgeSeconds: 600 }), 'iat', 'expired')
  })
})

describe('exp', () => {
  // RFC 7519: a token must not be accepted on or after its expiration time
  it('rejects a token that expires at now when there is no skew', async () => {
    await expectRejectedClaim(verify({ exp: secondsFromNow(0) }, { skewSeconds: 0 }), 'exp', 'expired')
  })

  it('accepts a token that expires a second after now when there is no skew', async () => {
    const { payload } = await verify({ exp: secondsFromNow(1) }, { skewSeconds: 0 })

    expect(payload.exp).toBe(secondsFromNow(1))
  })

  it('accepts a token that expired 29 seconds before now, within the default skew', async () => {
    const { payload } = await verify({ exp: secondsFromNow(-29) })

    expect(payload.exp).toBe(secondsFromNow(-29))
  })

  it('rejects a token that expired 30 seconds before now', async () => {
    await expectRejectedClaim(verify({ exp: secondsFromNow(-30) }), 'exp', 'expired')
  })

  it('accepts a token without exp', async () => {
    const { payload } = await verify({})

    expect(payload.exp).toBeUndefined()
  })

  // ISO/IEC 18013-5 second edition § 12.3.6.3 requires it for the revocation list of an MSO
  it('rejects a token without exp when it is required', async () => {
    await expectRejectedClaim(verify({}, { requiredClaims: ['exp'] }), 'exp', 'missing')
  })

  it('does not compare exp with now when checkExpirationTime is false', async () => {
    const { payload } = await verify({ exp: secondsFromNow(-3600) }, { checkExpirationTime: false })

    expect(payload.exp).toBe(secondsFromNow(-3600))
  })
})

describe('nbf', () => {
  it('accepts a token valid from 30 seconds after now, within the default skew', async () => {
    const { payload } = await verify({ nbf: secondsFromNow(30) })

    expect(payload.nbf).toBe(secondsFromNow(30))
  })

  it('rejects a token that is valid from more than 30 seconds after now', async () => {
    await expectRejectedClaim(verify({ nbf: secondsFromNow(31) }), 'nbf', 'not-yet-valid')
  })
})

describe('ttl', () => {
  it('returns the ttl of the token', async () => {
    const { payload } = await verify({ ttl: 300 })

    expect(payload.ttl).toBe(300)
  })

  // `ttl` says how long the token may be cached before a fresh one should be fetched, it is not an
  // expiration time. A verifier that wants a recent token sets `maxAgeSeconds`.
  it('accepts a token issued longer ago than its ttl', async () => {
    const { payload } = await verify({ iat: secondsFromNow(-3600), ttl: 60 })

    expect(payload.ttl).toBe(60)
  })
})

it('reports a claim that does not verify with the errorMessage it is given', async () => {
  await expect(verify({ exp: secondsFromNow(-3600) }, { errorMessage: 'Status list rejected.' })).rejects.toThrow(
    "Status list rejected. The 'exp' claim"
  )
})
