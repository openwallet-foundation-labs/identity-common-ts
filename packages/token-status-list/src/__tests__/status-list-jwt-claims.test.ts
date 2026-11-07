import { base64url, stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { JWT_STATUS_LIST_TYPE } from '../jwt-types'
import { StatusList } from '../status-list'
import { StatusListEntryNotValidError, StatusListError } from '../status-list-error'
import {
  type VerifyStatusListJwtSignature,
  verifyStatus,
  verifyStatusListJwtClaims,
  verifyStatusListJwtHeader,
} from '../status-list-jwt'
import { StatusType } from '../types'

const uri = 'https://example.com/statuslists/1'
const seconds = (date: number) => Math.floor(date / 1000)

/**
 * A Status List Token in JWT format. `claims` and `header` are merged over the claims and the header
 * a conformant token carries, so a claim can be overridden, or dropped by setting it to `undefined`.
 *
 * The token is not signed: the tests of the header and the claims verify it with `verify`, which accepts any
 * signature. The signature itself is tested with a signed token below.
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

const verify = (options: Omit<Parameters<typeof verifyStatus>[0], 'verifySignature'>) =>
  verifyStatus({ ...options, verifySignature: () => true })

describe('verifyStatus (JWT)', () => {
  // Regression: the subject was read from a `subject` claim, which a conformant Status List Token
  // never carries (the registered claim is `sub`), so every token was rejected as published for a
  // different uri.
  it('accepts a token whose claims are in order', async () => {
    await expect(verify({ uri, idx: 0, token: statusListToken() })).resolves.toStrictEqual(true)
  })

  it('rejects a token without a typ header', async () => {
    await expect(verify({ uri, idx: 0, token: statusListToken({}, [], { typ: undefined }) })).rejects.toThrow(
      'has no typ header'
    )
  })

  it('rejects a token whose typ header is not statuslist+jwt', async () => {
    await expect(verify({ uri, idx: 0, token: statusListToken({}, [], { typ: 'JWT' }) })).rejects.toThrow(
      "The typ header 'JWT' must be equal to 'statuslist+jwt'"
    )
  })

  // RFC 7515 section 4.1.9: a recipient treats a `typ` without a `/` as if `application/` were prepended
  it('accepts a typ header with the application/ prefix', async () => {
    const token = statusListToken({}, [], { typ: 'application/statuslist+jwt' })

    await expect(verify({ uri, idx: 0, token })).resolves.toStrictEqual(true)
  })

  it('rejects a token without a subject', async () => {
    await expect(verify({ uri, idx: 0, token: statusListToken({ sub: undefined }) })).rejects.toThrow(
      'has no subject claim'
    )
  })

  it('rejects a token published for a different uri', async () => {
    await expect(verify({ uri, idx: 0, token: statusListToken({ sub: 'https://example.com/other' }) })).rejects.toThrow(
      'must be equal to the uri'
    )
  })

  it('rejects a token without an issued at', async () => {
    await expect(verify({ uri, idx: 0, token: statusListToken({ iat: undefined }) })).rejects.toThrow(
      'has no issued at claim'
    )
  })

  it('rejects a revoked index', async () => {
    await expect(verify({ uri, idx: 3, token: statusListToken({}, [3]) })).rejects.toThrow(
      "Status for id '3' is not Valid"
    )
  })

  it('reports a status that is not Valid with its index and status', async () => {
    const verification = verify({ uri, idx: 3, token: statusListToken({}, [3]) })

    await expect(verification).rejects.toThrow(StatusListEntryNotValidError)
    await expect(verification).rejects.toThrow(StatusListError)
    await expect(verification).rejects.toThrow(expect.objectContaining({ idx: 3, status: StatusType.Invalid }))
  })

  it('returns the header it verified, with its alg', () => {
    const header = { alg: 'ES256', typ: JWT_STATUS_LIST_TYPE, kid: 'key-1' }

    const verified = verifyStatusListJwtHeader(header)

    expect(verified).toBe(header)
    expect(verified.alg.toUpperCase()).toStrictEqual('ES256')
  })

  it('rejects a token without an alg header', async () => {
    await expect(verify({ uri, idx: 0, token: statusListToken({}, [], { alg: undefined }) })).rejects.toThrow(
      'The status list token has no alg header, which is required'
    )
  })

  it.each([
    { name: 'no status_list', claims: { status_list: undefined } },
    {
      name: 'an lst that is not deflate',
      claims: { status_list: { bits: 1, lst: base64url.encode(new Uint8Array([1, 2, 3])) } },
    },
  ])('rejects a token with $name as an StatusListError', async ({ claims }) => {
    const verification = verify({ uri, idx: 0, token: statusListToken(claims) })

    await expect(verification).rejects.toThrow(StatusListError)
    await expect(verification).rejects.toThrow('The status list token has no valid status_list claim')
    await expect(verification).rejects.not.toThrow(StatusListEntryNotValidError)
  })

  it('verifies the header and the claims before reading the status list', async () => {
    const token = statusListToken({ sub: 'https://example.com/other', status_list: undefined })

    await expect(verify({ uri, idx: 0, token })).rejects.toThrow('must be equal to the uri')
  })

  it('applies the clock skew to the expiration', async () => {
    const token = statusListToken({ exp: seconds(Date.now() - 10_000) })

    await expect(verify({ uri, idx: 0, token })).resolves.toStrictEqual(true)
    await expect(verify({ uri, idx: 0, token, skewSeconds: 1 })).rejects.toThrow('is in the past')
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

  it('applies the clock skew to the issuance time', async () => {
    const token = statusListToken({ iat: seconds(Date.now() + 10_000) })

    await expect(verify({ uri, idx: 0, token })).resolves.toStrictEqual(true)
    await expect(verify({ uri, idx: 0, token, skewSeconds: 1 })).rejects.toThrow('is in the future')
  })

  it('does not compare the issuance time when freshness checking is disabled', async () => {
    const token = statusListToken({ iat: seconds(Date.now() + 60_000) })

    await expect(verify({ uri, idx: 0, token, checkFreshness: false })).resolves.toStrictEqual(true)
  })

  it('rejects a token that is not valid yet', async () => {
    const token = statusListToken({ nbf: seconds(Date.now() + 60_000) })

    await expect(verify({ uri, idx: 0, token })).rejects.toThrow('The not before claim')
    await expect(verify({ uri, idx: 0, token })).rejects.toThrow('is in the future')
  })

  it('can require an expiration, as ISO/IEC 18013-5 does for an MSO revocation list', async () => {
    await expect(verify({ uri, idx: 0, token: statusListToken(), requireExpirationTime: true })).rejects.toThrow(
      'has no expiration claim'
    )
    await expect(
      verify({
        uri,
        idx: 0,
        token: statusListToken({ exp: seconds(Date.now() + 60_000) }),
        requireExpirationTime: true,
      })
    ).resolves.toStrictEqual(true)
  })
})

// Token Status List Section 8.3: the claims and the status list are only the issuer's once the signature verified
describe('verifyStatus (JWT) signature', () => {
  const ecdsa = { name: 'ECDSA', hash: 'SHA-256' }
  const generateKey = () =>
    crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ]) as Promise<CryptoKeyPair>

  const signedStatusListToken = async (privateKey: CryptoKey, header: Record<string, unknown> = {}) => {
    const signingInput = statusListToken({}, [], header).slice(0, -1)
    const signature = await crypto.subtle.sign(ecdsa, privateKey, stringToBytes(signingInput))
    return `${signingInput}.${base64url.encode(new Uint8Array(signature))}`
  }

  const verifyWith =
    (publicKey: CryptoKey): VerifyStatusListJwtSignature =>
    ({ signingInput, signature }) =>
      crypto.subtle.verify(ecdsa, publicKey, signature as BufferSource, signingInput as BufferSource)

  it('verifies the signature with verifySignature', async () => {
    const issuer = await generateKey()
    const token = await signedStatusListToken(issuer.privateKey)

    await expect(verifyStatus({ uri, idx: 0, token, verifySignature: verifyWith(issuer.publicKey) })).resolves.toBe(
      true
    )
  })

  it.each([
    ['signed with another key', async () => signedStatusListToken((await generateKey()).privateKey)],
    ['not signed', async () => statusListToken()],
  ])('rejects a token %s', async (_description, createToken) => {
    const issuer = await generateKey()

    await expect(
      verifyStatus({ uri, idx: 0, token: await createToken(), verifySignature: verifyWith(issuer.publicKey) })
    ).rejects.toThrow('The signature of the status list token is not valid')
  })

  // RFC 7515 Section 4.1.11: a critical extension the recipient does not understand is rejected
  it('rejects a token with a crit header', async () => {
    const issuer = await generateKey()
    const token = await signedStatusListToken(issuer.privateKey, { crit: ['exp'] })

    await expect(verifyStatus({ uri, idx: 0, token, verifySignature: verifyWith(issuer.publicKey) })).rejects.toThrow(
      'has a crit header'
    )
  })
})
