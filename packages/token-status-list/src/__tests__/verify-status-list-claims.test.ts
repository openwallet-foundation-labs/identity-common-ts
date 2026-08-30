import { base64url, stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import type { JWT_STATUS_LIST_TYPE } from '../jwt-types'
import { StatusList } from '../status-list'
import { createHeaderAndPayload, verifyStatus } from '../status-list-jwt'
import { StatusType } from '../types'
import { verifyStatusListClaims } from '../verify-status-list-claims'

const uri = 'https://example.com/statuslists/1'

const claims = (overrides: Partial<Parameters<typeof verifyStatusListClaims>[0]['claims']> = {}) => ({
  subject: uri,
  issuedAt: new Date(Date.now() - 60_000),
  expirationTime: new Date(Date.now() + 60_000),
  ...overrides,
})

describe('verifyStatusListClaims', () => {
  it('accepts a token whose claims are in order', () => {
    expect(() => verifyStatusListClaims({ claims: claims(), uri })).not.toThrow()
  })

  it('rejects a token without a subject', () => {
    expect(() => verifyStatusListClaims({ claims: claims({ subject: undefined }), uri })).toThrow(
      'has no subject claim'
    )
  })

  it('rejects a token published for a different uri', () => {
    expect(() =>
      verifyStatusListClaims({ claims: claims({ subject: 'https://example.com/statuslists/2' }), uri })
    ).toThrow('must be equal to the uri')
  })

  it('rejects a token without an issued at', () => {
    expect(() => verifyStatusListClaims({ claims: claims({ issuedAt: undefined }), uri })).toThrow(
      'has no issued at claim'
    )
  })

  it('accepts a missing expiration by default, and rejects it for a profile that requires one', () => {
    expect(() => verifyStatusListClaims({ claims: claims({ expirationTime: undefined }), uri })).not.toThrow()
    expect(() =>
      verifyStatusListClaims({ claims: claims({ expirationTime: undefined }), uri, requireExpirationTime: true })
    ).toThrow('has no expiration claim')
  })

  it('applies the clock skew to the expiration', () => {
    const expired = claims({ expirationTime: new Date(Date.now() - 10_000) })

    expect(() => verifyStatusListClaims({ claims: expired, uri })).not.toThrow()
    expect(() => verifyStatusListClaims({ claims: expired, uri, skewSeconds: 1 })).toThrow('is in the past')
  })

  it('applies the clock skew to the issuance time', () => {
    const notYetIssued = claims({ issuedAt: new Date(Date.now() + 10_000) })

    expect(() => verifyStatusListClaims({ claims: notYetIssued, uri })).not.toThrow()
    expect(() => verifyStatusListClaims({ claims: notYetIssued, uri, skewSeconds: 1 })).toThrow('is in the future')
  })

  it('does not compare the issuance time when freshness checking is disabled', () => {
    const notYetIssued = claims({ issuedAt: new Date(Date.now() + 60_000) })

    expect(() => verifyStatusListClaims({ claims: notYetIssued, uri, checkFreshness: false })).not.toThrow()
  })
})

describe('verifyStatus (JWT)', () => {
  const statusListToken = ({
    sub = uri,
    iat = Math.floor((Date.now() - 60_000) / 1000),
    exp,
    revokedIndexes = [] as Array<number>,
  }: {
    sub?: string
    iat?: number
    exp?: number
    revokedIndexes?: Array<number>
  } = {}) => {
    const statusList = new StatusList(new Array(10).fill(StatusType.Valid), 1)
    for (const index of revokedIndexes) statusList.setStatus(index, StatusType.Invalid)

    const { header, payload } = createHeaderAndPayload(
      statusList,
      { sub, iat, ...(exp === undefined ? {} : { exp }) },
      { alg: 'ES256', typ: '' as typeof JWT_STATUS_LIST_TYPE }
    )

    // The signature is not inspected by `verifyStatus`; callers verify it separately.
    return `${base64url.encode(stringToBytes(JSON.stringify(header)))}.${base64url.encode(
      stringToBytes(JSON.stringify(payload))
    )}.`
  }

  // Regression: the subject was read from a `subject` claim, which a conformant token never
  // carries, so every token was rejected as published for a different uri.
  it('reads the subject from the registered sub claim', () => {
    expect(verifyStatus({ uri, idx: 0, token: statusListToken() })).toStrictEqual(true)
  })

  it('rejects a token published for a different uri', () => {
    expect(() => verifyStatus({ uri, idx: 0, token: statusListToken({ sub: 'https://example.com/other' }) })).toThrow(
      'must be equal to the uri'
    )
  })

  it('rejects a revoked index', () => {
    expect(() => verifyStatus({ uri, idx: 3, token: statusListToken({ revokedIndexes: [3] }) })).toThrow(
      "Status for id '3' is not Valid"
    )
  })

  it('applies the clock skew to the expiration', () => {
    const token = statusListToken({ exp: Math.floor((Date.now() - 10_000) / 1000) })

    expect(verifyStatus({ uri, idx: 0, token })).toStrictEqual(true)
    expect(() => verifyStatus({ uri, idx: 0, token, skewSeconds: 1 })).toThrow('is in the past')
  })

  it('can require an expiration, as ISO/IEC 18013-5 does for an MSO revocation list', () => {
    expect(() => verifyStatus({ uri, idx: 0, token: statusListToken(), requireExpirationTime: true })).toThrow(
      'has no expiration claim'
    )
  })
})
