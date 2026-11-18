import { dateToSeconds } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { JoseInvalidArgumentError, JoseValidationError } from '../error'
import { signJwt } from '../jwt/sign-jwt'
import { verifyJwt } from '../jwt/verify-jwt'
import { verifyJwtClaims } from '../jwt/verify-jwt-claims'
import type { JwtPayload } from '../jwt/z-jwt'
import { claimIssue, createEs256Context } from './context'

const now = new Date('2026-09-15T12:00:00Z')
const expiredAnHourAgo = { exp: dateToSeconds(now) - 3600 }
const prefix = 'Error during verification of the JWT claims.'

/**
 * Every time check compares against `now` shifted by the skew. With `NaN` in either, every comparison
 * is false, which would accept any token — `Number(process.env.SKEW)` is `NaN` when the variable is
 * not set.
 */
describe('options that cannot be used to verify the time claims', () => {
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1])(
    'rejects skewSeconds %s',
    (skewSeconds) => {
      expect(() => verifyJwtClaims(expiredAnHourAgo, { now, skewSeconds })).toThrow(
        new JoseInvalidArgumentError(
          `${prefix} The 'skewSeconds' option must be a finite number of at least 0, but is '${skewSeconds}'.`
        )
      )
    }
  )

  it.each([Number.NaN, Number.POSITIVE_INFINITY, -1])('rejects maxAgeSeconds %s', (maxAgeSeconds) => {
    expect(() => verifyJwtClaims({ iat: dateToSeconds(now) - 36000 }, { now, maxAgeSeconds })).toThrow(
      new JoseInvalidArgumentError(
        `${prefix} The 'maxAgeSeconds' option must be a finite number of at least 0, but is '${maxAgeSeconds}'.`
      )
    )
  })

  it('rejects a now that is an invalid date', () => {
    expect(() => verifyJwtClaims(expiredAnHourAgo, { now: new Date('not a date') })).toThrow(
      new JoseInvalidArgumentError(`${prefix} The 'now' option must be a valid date.`)
    )
  })

  it('rejects a now that is not a date', () => {
    expect(() => verifyJwtClaims(expiredAnHourAgo, { now: dateToSeconds(now) as unknown as Date })).toThrow(
      new JoseInvalidArgumentError(`${prefix} The 'now' option must be a valid date.`)
    )
  })

  it('rejects invalid options for a token that has no time claims', () => {
    expect(() => verifyJwtClaims({}, { now, skewSeconds: Number.NaN })).toThrow(JoseInvalidArgumentError)
  })

  it('does not report invalid options as a claim that did not verify', () => {
    // Caught rather than asserted with `not.toThrow(JoseValidationError)`, which also passes
    // when nothing is thrown at all — which is what a NaN skew used to do for this expired token
    let error: unknown
    try {
      verifyJwtClaims(expiredAnHourAgo, { now, skewSeconds: Number.NaN })
    } catch (caught) {
      error = caught
    }

    expect(error).toBeInstanceOf(JoseInvalidArgumentError)
    expect(error).not.toBeInstanceOf(JoseValidationError)
  })

  it('accepts a skewSeconds of 0', () => {
    expect(() => verifyJwtClaims({ exp: dateToSeconds(now) + 1 }, { now, skewSeconds: 0 })).not.toThrow()
  })

  it('accepts a maxAgeSeconds of 0 for a token issued at this very moment', () => {
    expect(() => verifyJwtClaims({ iat: dateToSeconds(now) }, { now, skewSeconds: 0, maxAgeSeconds: 0 })).not.toThrow()
  })

  it('rejects a skewSeconds of NaN when verifying an expired JWT with a valid signature', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()
    const { jwt } = await signJwt({
      payload: expiredAnHourAgo,
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
    })

    await expect(verifyJwt({ jwt, verifyJwsCallback: verifyJws, now, skewSeconds: Number.NaN })).rejects.toThrow(
      JoseInvalidArgumentError
    )
  })
})

/**
 * A `Date` holds up to 8.64e15 milliseconds either side of 1970, but a NumericDate is any JSON number.
 * The time claims are compared as numbers of seconds, so one outside the range of a `Date` still
 * orders: an `exp` of 9999999999999 is a token that does not expire. An issue message prints such a
 * NumericDate as the number, as it has no date to print.
 */
describe('a NumericDate outside the range of a Date', () => {
  it.each([9999999999999, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE])(
    'accepts an exp of %d, as a token that does not expire',
    (exp) => {
      expect(() => verifyJwtClaims({ exp }, { now })).not.toThrow()
    }
  )

  it('rejects an exp far in the past as expired', () => {
    expect(() => verifyJwtClaims({ exp: -1e13 }, { now })).toThrow(
      claimIssue(
        'exp',
        'expired',
        `The 'exp' claim '-10000000000000' is in the past (compared to '2026-09-15T12:00:00.000Z')`
      )
    )
  })

  it.each(['nbf', 'iat'])('rejects an %s far in the future as not yet valid', (claim) => {
    expect(() => verifyJwtClaims({ [claim]: 1e13 }, { now })).toThrow(
      claimIssue(
        claim,
        'not_yet_valid',
        `The '${claim}' claim '10000000000000' is in the future (compared to '2026-09-15T12:00:00.000Z')`
      )
    )
  })

  it.each(['nbf', 'iat'])('accepts an %s far in the past', (claim) => {
    expect(() => verifyJwtClaims({ [claim]: -1e13 }, { now })).not.toThrow()
  })

  it('rejects an iat far in the past as older than maxAgeSeconds', () => {
    expect(() => verifyJwtClaims({ iat: -1e13 }, { now, maxAgeSeconds: 60 })).toThrow(
      claimIssue(
        'iat',
        'expired',
        `The 'iat' claim '-10000000000000' is more than 60 seconds in the past (compared to '2026-09-15T12:00:00.000Z')`
      )
    )
  })

  it('accepts an iat far in the future against maxAgeSeconds when the iat is not checked', () => {
    expect(() => verifyJwtClaims({ iat: 1e13 }, { now, checkIssuedAt: false, maxAgeSeconds: 60 })).not.toThrow()
  })

  it('accepts an exp at the last instant a date can hold', () => {
    expect(() => verifyJwtClaims({ exp: 8.64e12 }, { now })).not.toThrow()
  })

  it('rejects an nbf at the last instant a date can hold as not yet valid', () => {
    expect(() => verifyJwtClaims({ nbf: 8.64e12 }, { now })).toThrow(
      claimIssue(
        'nbf',
        'not_yet_valid',
        `The 'nbf' claim '+275760-09-13T00:00:00.000Z' is in the future (compared to '2026-09-15T12:00:00.000Z')`
      )
    )
  })

  it('does not look at an exp far in the past when the expiration time is not checked', () => {
    expect(() => verifyJwtClaims({ exp: -1e13 }, { now, checkExpirationTime: false })).not.toThrow()
  })

  it('accepts a signed JWT whose exp is 9999999999999', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()
    const { jwt } = await signJwt({
      payload: { exp: 9999999999999 },
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
    })

    const { payload } = await verifyJwt({ jwt, verifyJwsCallback: verifyJws, now })

    expect(payload.exp).toBe(9999999999999)
  })

  it('rejects a signed JWT whose exp is far in the past as expired', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()
    const { jwt } = await signJwt({
      payload: { exp: -1e13 },
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
    })

    await expect(verifyJwt({ jwt, verifyJwsCallback: verifyJws, now })).rejects.toThrow(claimIssue('exp', 'expired'))
  })
})

/**
 * A payload that reached `verifyJwtClaims` without `zJwtPayload` — which only lets finite numbers
 * through — can carry a time claim that is not a number at all. With `NaN`, every comparison against
 * `now` would be false and accept the token.
 */
describe('a time claim that is not a finite number', () => {
  it.each([
    ['exp', Number.NaN],
    ['exp', Number.POSITIVE_INFINITY],
    ['exp', Number.NEGATIVE_INFINITY],
    ['nbf', Number.NaN],
    ['iat', Number.POSITIVE_INFINITY],
  ])('rejects an %s of %d as an invalid claim', (claim, value) => {
    expect(() => verifyJwtClaims({ [claim]: value }, { now })).toThrow(
      claimIssue(claim, 'invalid_type', `The '${claim}' claim '${value}' is not a NumericDate`)
    )
  })

  it('rejects an iat of NaN against maxAgeSeconds as an invalid claim', () => {
    expect(() => verifyJwtClaims({ iat: Number.NaN }, { now, checkIssuedAt: false, maxAgeSeconds: 60 })).toThrow(
      claimIssue('iat', 'invalid_type', `The 'iat' claim 'NaN' is not a NumericDate`)
    )
  })

  it('rejects an exp that is a string as an invalid claim', () => {
    const payload = { exp: '1700000000' } as unknown as JwtPayload

    expect(() => verifyJwtClaims(payload, { now })).toThrow(
      claimIssue('exp', 'invalid_type', `The 'exp' claim '1700000000' is not a NumericDate`)
    )
  })
})
