import { base64url, stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { JWT_STATUS_LIST_TYPE } from '../jwt-types'
import { StatusList } from '../status-list'
import { SLException, StatusListEntryNotValidException } from '../status-list-exception'
import { verifyStatus, verifyStatusListJwtClaims } from '../status-list-jwt'
import { StatusType } from '../types'

const uri = 'https://example.com/statuslists/1'
const seconds = (date: number) => Math.floor(date / 1000)

/**
 * A Status List Token in JWT format. `claims` and `header` are merged over the claims and the header
 * a conformant token carries, so a claim can be overridden, or dropped by setting it to `undefined`.
 *
 * The signature is not inspected by `verifyStatus`; callers verify it separately.
 */
const statusListToken = (
  claims: Record<string, unknown> = {},
  revokedIndexes: Array<number> = [],
  header: Record<string, unknown> = {}
) => {
  const statusList = new StatusList(new Array(10).fill(StatusType.Valid), 1)
  for (const index of revokedIndexes) statusList.setStatus(index, StatusType.Invalid)

  const encode = (value: unknown) => base64url.encode(stringToBytes(JSON.stringify(value)))

  return `${encode({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE, ...header })}.${encode({
    sub: uri,
    iat: seconds(Date.now() - 60_000),
    status_list: {
      bits: statusList.getBitsPerStatus(),
      lst: base64url.encode(statusList.compressStatusListToBytes()),
    },
    ...claims,
  })}.`
}

describe('verifyStatus (JWT)', () => {
  // Regression: the subject was read from a `subject` claim, which a conformant Status List Token
  // never carries (the registered claim is `sub`), so every token was rejected as published for a
  // different uri.
  it('accepts a token whose claims are in order', () => {
    expect(verifyStatus({ uri, idx: 0, token: statusListToken() })).toStrictEqual(true)
  })

  it('rejects a token without a typ header', () => {
    expect(() => verifyStatus({ uri, idx: 0, token: statusListToken({}, [], { typ: undefined }) })).toThrow(
      'has no typ header'
    )
  })

  it('rejects a token whose typ header is not statuslist+jwt', () => {
    expect(() => verifyStatus({ uri, idx: 0, token: statusListToken({}, [], { typ: 'JWT' }) })).toThrow(
      "The typ header 'JWT' must be equal to 'statuslist+jwt'"
    )
  })

  // RFC 7515 section 4.1.9: a recipient treats a `typ` without a `/` as if `application/` were prepended
  it('accepts a typ header with the application/ prefix', () => {
    const token = statusListToken({}, [], { typ: 'application/statuslist+jwt' })

    expect(verifyStatus({ uri, idx: 0, token })).toStrictEqual(true)
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

  it('reports a status that is not Valid with its index and status', () => {
    const verification = () => verifyStatus({ uri, idx: 3, token: statusListToken({}, [3]) })

    expect(verification).toThrow(StatusListEntryNotValidException)
    expect(verification).toThrow(SLException)
    expect(verification).toThrow(expect.objectContaining({ idx: 3, status: StatusType.Invalid }))
  })

  it('rejects a token without an alg header', () => {
    expect(() => verifyStatus({ uri, idx: 0, token: statusListToken({}, [], { alg: undefined }) })).toThrow(
      'The status list token has no alg header, which is required'
    )
  })

  it.each([
    { name: 'no status_list', claims: { status_list: undefined } },
    {
      name: 'an lst that is not deflate',
      claims: { status_list: { bits: 1, lst: base64url.encode(new Uint8Array([1, 2, 3])) } },
    },
  ])('rejects a token with $name as an SLException', ({ claims }) => {
    const verification = () => verifyStatus({ uri, idx: 0, token: statusListToken(claims) })

    expect(verification).toThrow(SLException)
    expect(verification).toThrow('The status list token has no valid status_list claim')
    expect(verification).not.toThrow(StatusListEntryNotValidException)
  })

  it('verifies the header and the claims before reading the status list', () => {
    const token = statusListToken({ sub: 'https://example.com/other', status_list: undefined })

    expect(() => verifyStatus({ uri, idx: 0, token })).toThrow('must be equal to the uri')
  })

  it('applies the clock skew to the expiration', () => {
    const token = statusListToken({ exp: seconds(Date.now() - 10_000) })

    expect(verifyStatus({ uri, idx: 0, token })).toStrictEqual(true)
    expect(() => verifyStatus({ uri, idx: 0, token, skewSeconds: 1 })).toThrow('is in the past')
  })

  // RFC 7519 section 4.1.4: `exp` is the time "on or after which the JWT MUST NOT be accepted"
  it('rejects a token at the instant it expires', () => {
    const exp = seconds(Date.parse('2026-01-01T12:00:00.000Z'))
    const claims = { sub: uri, iat: exp - 60, exp, status_list: { bits: 1 as const, lst: '' } }

    expect(() => verifyStatusListJwtClaims(claims, { uri, now: new Date(exp * 1000), skewSeconds: 0 })).toThrow(
      'is in the past'
    )
    expect(() =>
      verifyStatusListJwtClaims(claims, { uri, now: new Date(exp * 1000 - 1), skewSeconds: 0 })
    ).not.toThrow()
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
