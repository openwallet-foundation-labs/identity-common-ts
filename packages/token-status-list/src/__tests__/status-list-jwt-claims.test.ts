import { base64url, stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { JWT_STATUS_LIST_TYPE } from '../jwt-types'
import { StatusList } from '../status-list'
import { verifyStatus } from '../status-list-jwt'
import { StatusType } from '../types'

const uri = 'https://example.com/statuslists/1'
const seconds = (date: number) => Math.floor(date / 1000)

/**
 * A Status List Token in JWT format. `claims` is merged over the claims a conformant token carries,
 * so a claim can be overridden, or dropped by setting it to `undefined`.
 *
 * The signature is not inspected by `verifyStatus`; callers verify it separately.
 */
const statusListToken = (claims: Record<string, unknown> = {}, revokedIndexes: Array<number> = []) => {
  const statusList = new StatusList(new Array(10).fill(StatusType.Valid), 1)
  for (const index of revokedIndexes) statusList.setStatus(index, StatusType.Invalid)

  const encode = (value: unknown) => base64url.encode(stringToBytes(JSON.stringify(value)))

  return `${encode({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE })}.${encode({
    sub: uri,
    iat: seconds(Date.now() - 60_000),
    ...claims,
    status_list: {
      bits: statusList.getBitsPerStatus(),
      lst: base64url.encode(statusList.compressStatusListToBytes()),
    },
  })}.`
}

describe('verifyStatus (JWT)', () => {
  // Regression: the subject was read from a `subject` claim, which a conformant Status List Token
  // never carries (the registered claim is `sub`), so every token was rejected as published for a
  // different uri.
  it('accepts a token whose claims are in order', () => {
    expect(verifyStatus({ uri, idx: 0, token: statusListToken() })).toStrictEqual(true)
  })

  it('rejects a token without a subject', () => {
    expect(() => verifyStatus({ uri, idx: 0, token: statusListToken({ sub: undefined }) })).toThrow(
      'has no subject claim'
    )
  })

  it('rejects a token published for a different uri', () => {
    expect(() => verifyStatus({ uri, idx: 0, token: statusListToken({ sub: 'https://example.com/other' }) })).toThrow(
      'must be equal to the uri'
    )
  })

  it('rejects a token without an issued at', () => {
    expect(() => verifyStatus({ uri, idx: 0, token: statusListToken({ iat: undefined }) })).toThrow(
      'has no issued at claim'
    )
  })

  it('rejects a revoked index', () => {
    expect(() => verifyStatus({ uri, idx: 3, token: statusListToken({}, [3]) })).toThrow(
      "Status for id '3' is not Valid"
    )
  })

  it('applies the clock skew to the expiration', () => {
    const token = statusListToken({ exp: seconds(Date.now() - 10_000) })

    expect(verifyStatus({ uri, idx: 0, token })).toStrictEqual(true)
    expect(() => verifyStatus({ uri, idx: 0, token, skewSeconds: 1 })).toThrow('is in the past')
  })

  it('applies the clock skew to the issuance time', () => {
    const token = statusListToken({ iat: seconds(Date.now() + 10_000) })

    expect(verifyStatus({ uri, idx: 0, token })).toStrictEqual(true)
    expect(() => verifyStatus({ uri, idx: 0, token, skewSeconds: 1 })).toThrow('is in the future')
  })

  it('does not compare the issuance time when freshness checking is disabled', () => {
    const token = statusListToken({ iat: seconds(Date.now() + 60_000) })

    expect(verifyStatus({ uri, idx: 0, token, checkFreshness: false })).toStrictEqual(true)
  })

  it('rejects a token that is not valid yet', () => {
    const token = statusListToken({ nbf: seconds(Date.now() + 60_000) })

    expect(() => verifyStatus({ uri, idx: 0, token })).toThrow('The not before claim')
    expect(() => verifyStatus({ uri, idx: 0, token })).toThrow('is in the future')
  })

  it('can require an expiration, as ISO/IEC 18013-5 does for an MSO revocation list', () => {
    expect(() => verifyStatus({ uri, idx: 0, token: statusListToken(), requireExpirationTime: true })).toThrow(
      'has no expiration claim'
    )
    expect(
      verifyStatus({
        uri,
        idx: 0,
        token: statusListToken({ exp: seconds(Date.now() + 60_000) }),
        requireExpirationTime: true,
      })
    ).toStrictEqual(true)
  })
})
