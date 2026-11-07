import { base64url, stringToBytes } from '@owf/identity-common'
import { JoseValidationError } from '@owf/jose'
import { describe, expect, it } from 'vitest'
import { JWT_STATUS_LIST_TYPE } from '../jwt-types'
import { StatusList } from '../status-list'
import {
  decodeStatusListJwt,
  type VerifyStatusListJwtClaimsOptions,
  verifyStatusListJwtClaims,
} from '../status-list-jwt'
import { StatusType } from '../types'

const uri = 'https://example.com/statuslists/1'
const seconds = (date: number) => Math.floor(date / 1000)

/**
 * A Status List Token in JWT format. `claims` and `header` are merged over the claims and the header
 * a conformant token carries, so a claim can be overridden, or dropped by setting it to `undefined`.
 *
 * The signature is not inspected when decoding or verifying the claims, but it has to be there: a
 * token without one is an unsecured JWS, which is not decoded at all.
 */
const statusListToken = (claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}) => {
  const statusList = new StatusList(new Array(10).fill(StatusType.Valid), 1)
  const encode = (value: unknown) => base64url.encode(stringToBytes(JSON.stringify(value)))

  return `${encode({ alg: 'ES256', typ: JWT_STATUS_LIST_TYPE, ...header })}.${encode({
    sub: uri,
    iat: seconds(Date.now() - 60_000),
    ...claims,
    status_list: {
      bits: statusList.getBitsPerStatus(),
      lst: base64url.encode(statusList.compressStatusListToBytes()),
    },
  })}.${base64url.encode(stringToBytes('not-verified'))}`
}

const verifyClaims = (token: string, options: Partial<VerifyStatusListJwtClaimsOptions> = {}) =>
  verifyStatusListJwtClaims(decodeStatusListJwt(token).payload, { uri, ...options })

describe('verifyStatusListJwtClaims', () => {
  // Regression: the subject was read from a `subject` claim, which a conformant Status List Token
  // never carries (the registered claim is `sub`), so every token was rejected as published for a
  // different uri.
  it('accepts a token whose claims are in order', () => {
    expect(() => verifyClaims(statusListToken())).not.toThrow()
  })

  // A token without the `statuslist+jwt` typ is rejected when decoded
  it('rejects a token without a typ header', () => {
    expect(() => decodeStatusListJwt(statusListToken({}, { typ: undefined }))).toThrow(JoseValidationError)
    expect(() => decodeStatusListJwt(statusListToken({}, { typ: undefined }))).toThrow('- typ: ')
  })

  it('rejects a token whose typ header is not statuslist+jwt', () => {
    expect(() => decodeStatusListJwt(statusListToken({}, { typ: 'JWT' }))).toThrow(JoseValidationError)
    expect(() => decodeStatusListJwt(statusListToken({}, { typ: 'JWT' }))).toThrow(
      `typ: typ must be statuslist+jwt (invalid_typ)`
    )
  })

  it('rejects a token without an alg header', () => {
    expect(() => decodeStatusListJwt(statusListToken({}, { alg: undefined }))).toThrow(JoseValidationError)
    expect(() => decodeStatusListJwt(statusListToken({}, { alg: undefined }))).toThrow('- alg: ')
  })

  it('returns the header it decoded, with its alg', () => {
    expect(decodeStatusListJwt(statusListToken({}, { kid: 'key-1' })).header).toMatchObject({
      alg: 'ES256',
      typ: JWT_STATUS_LIST_TYPE,
      kid: 'key-1',
    })
  })

  // RFC 7515 section 4.1.9: a recipient treats a `typ` without a `/` as if `application/` were prepended
  it('accepts a typ header with the application/ prefix', () => {
    const token = statusListToken({}, { typ: 'application/statuslist+jwt' })

    expect(() => verifyClaims(token)).not.toThrow()
  })

  // A token without `sub` or `iat` is rejected when decoded
  it('rejects a token without a subject', () => {
    expect(() => decodeStatusListJwt(statusListToken({ sub: undefined }))).toThrow(JoseValidationError)
    expect(() => decodeStatusListJwt(statusListToken({ sub: undefined }))).toThrow('- sub: ')
  })

  it('rejects a token without an issued at', () => {
    expect(() => decodeStatusListJwt(statusListToken({ iat: undefined }))).toThrow(JoseValidationError)
    expect(() => decodeStatusListJwt(statusListToken({ iat: undefined }))).toThrow('- iat: ')
  })

  it('rejects a token published for a different uri', () => {
    expect(() => verifyClaims(statusListToken({ sub: 'https://example.com/other' }))).toThrow(
      `The 'sub' claim 'https://example.com/other' does not match the expected value '${uri}'`
    )
  })

  it('applies the clock skew to the expiration', () => {
    const token = statusListToken({ exp: seconds(Date.now() - 10_000) })

    expect(() => verifyClaims(token)).not.toThrow()
    expect(() => verifyClaims(token, { skewSeconds: 1 })).toThrow('is in the past')
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

    expect(() => verifyClaims(token)).not.toThrow()
    expect(() => verifyClaims(token, { skewSeconds: 1 })).toThrow('is in the future')
  })

  it('does not compare the issuance time when checkIssuedAt is disabled', () => {
    const token = statusListToken({ iat: seconds(Date.now() + 60_000) })

    expect(() => verifyClaims(token, { checkIssuedAt: false })).not.toThrow()
  })

  it('rejects a token that is not valid yet', () => {
    const token = statusListToken({ nbf: seconds(Date.now() + 60_000) })

    expect(() => verifyClaims(token)).toThrow(`The 'nbf' claim`)
    expect(() => verifyClaims(token)).toThrow('is in the future')
  })

  it('can require an expiration, as ISO/IEC 18013-5 does for an MSO revocation list', () => {
    expect(() => verifyClaims(statusListToken(), { requiredClaims: ['exp'] })).toThrow(
      `The token has no 'exp' claim, which is required`
    )
    expect(() =>
      verifyClaims(statusListToken({ exp: seconds(Date.now() + 60_000) }), { requiredClaims: ['exp'] })
    ).not.toThrow()
  })
})
