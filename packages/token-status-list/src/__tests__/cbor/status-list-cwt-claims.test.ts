import { CoseInvalidSignatureError, CoseKey, RegisteredCwtClaimKey, SignatureAlgorithm } from '@owf/cose'
import { describe, expect, test } from 'vitest'
import { StatusListCwt } from '../../cbor/status-list-cwt'
import { type CreateStatusListCwtPayloadOptions, StatusListCwtPayload } from '../../cbor/status-list-cwt-payload'
import { StatusList } from '../../status-list'
import { SLException } from '../../status-list-exception'
import { StatusType } from '../../types'
import { sign1Context, signKey } from '../context'

// A second key pair, to check that a token does not verify against a key that did not sign it.
const otherSignKey = CoseKey.fromJwk({
  kty: 'EC',
  crv: 'P-256',
  alg: 'ES256',
  x: 'R7D-W2d9MEVRN_5P23yN9SodkjMEHI2Np_YHD02eTCQ',
  y: 'c5Ynunf6XyarMKXt0hWEezNzsZv01uQpCnpT-qJoll8',
})

const uri = 'https://example.com/statuslists/1'
const now = new Date('2026-01-01T12:00:00.000Z')
const minutes = (count: number) => new Date(now.getTime() + count * 60_000)

const statusList = (revokedIndexes: Array<number> = []) => {
  const list = new StatusList(new Array(10).fill(StatusType.Valid), 1)
  for (const index of revokedIndexes) list.setStatus(index, StatusType.Invalid)
  return list
}

const payload = (options: Partial<CreateStatusListCwtPayloadOptions> = {}) =>
  StatusListCwtPayload.create({
    subject: uri,
    issuedAt: minutes(-5),
    statusList: statusList(),
    ...options,
  })

describe('StatusListCwtPayload.verifyClaims', () => {
  test('accepts a token whose claims are in order', () => {
    expect(() => payload({ expirationTime: minutes(5) }).verifyClaims({ uri, now })).not.toThrow()
  })

  test('rejects a token published for a different uri', () => {
    expect(() => payload().verifyClaims({ uri: 'https://example.com/statuslists/2', now })).toThrow(SLException)
    expect(() => payload().verifyClaims({ uri: 'https://example.com/statuslists/2', now })).toThrow(
      `The 'Subject (2)' claim '${uri}' does not match the expected value 'https://example.com/statuslists/2'`
    )
  })

  test('rejects a token without the claims a status list token requires', () => {
    // `sub` and `iat` are REQUIRED, unlike for a plain CWT, so a payload without them is rejected
    // here even though the claims schema allows it
    const withoutSubject = StatusListCwtPayload.fromDecodedStructure(payload().claims)
    withoutSubject.claims.delete(2)

    expect(() => withoutSubject.verifyClaims({ uri, now })).toThrow("has no 'Subject (2)' claim, which is required")
  })

  test('applies the clock skew to the expiration', () => {
    const expired = payload({ expirationTime: minutes(-0.25) })

    expect(() => expired.verifyClaims({ uri, now })).not.toThrow()
    expect(() => expired.verifyClaims({ uri, now, skewSeconds: 1 })).toThrow('is in the past')
  })

  test('applies the clock skew to the issuance time, unless the issuance check is off', () => {
    const notYetIssued = payload({ issuedAt: minutes(0.25) })

    expect(() => notYetIssued.verifyClaims({ uri, now })).not.toThrow()
    expect(() => notYetIssued.verifyClaims({ uri, now, skewSeconds: 1 })).toThrow('is in the future')
    expect(() => notYetIssued.verifyClaims({ uri, now, skewSeconds: 1, checkIssuedAt: false })).not.toThrow()
  })

  test('can require an expiration, as ISO/IEC 18013-5 does for an MSO revocation list', () => {
    expect(() => payload().verifyClaims({ uri, now })).not.toThrow()
    expect(() => payload().verifyClaims({ uri, now, requiredClaims: [RegisteredCwtClaimKey.ExpirationTime] })).toThrow(
      "has no 'ExpirationTime (4)' claim"
    )
  })

  test('names a status list claim it is asked to require', () => {
    expect(() => payload().verifyClaims({ uri, now, requiredClaims: [65534] })).toThrow(
      "The token has no 'TimeToLive (65534)' claim, which is required"
    )
  })

  test('rejects an index that is not valid', () => {
    expect(() => payload({ statusList: statusList([3]) }).verifyStatus(3)).toThrow("Status for id '3' is not Valid")
    expect(() => payload({ statusList: statusList([3]) }).verifyStatus(2)).not.toThrow()
  })
})

describe('StatusListCwt.verify', () => {
  const token = async (options: Partial<CreateStatusListCwtPayloadOptions> = {}) =>
    await new StatusListCwt({ payload: payload(options) }).signAndEncode(
      { signingKey: signKey, algorithm: SignatureAlgorithm.ES256 },
      sign1Context
    )

  test('verifies the signature, the claims and the status at an index', async () => {
    const cwt = StatusListCwt.fromToken(await token({ statusList: statusList([3]) }))

    await expect(cwt.verify({ key: signKey, uri, now, idx: 0 }, { sign1: sign1Context })).resolves.toBeUndefined()
    await expect(cwt.verify({ key: signKey, uri, now, idx: 3 }, { sign1: sign1Context })).rejects.toThrow(
      "Status for id '3' is not Valid"
    )
  })

  test('rejects a token that does not verify with the given key, before looking at its claims', async () => {
    const cwt = StatusListCwt.fromToken(await token())

    await expect(cwt.verify({ key: otherSignKey, uri, now }, { sign1: sign1Context })).rejects.toThrow(
      CoseInvalidSignatureError
    )
  })

  test('rejects a verified token whose claims are not in order', async () => {
    const cwt = StatusListCwt.fromToken(await token())

    await expect(
      cwt.verify({ key: signKey, uri: 'https://example.com/other', now }, { sign1: sign1Context })
    ).rejects.toThrow(SLException)
  })

  test('checks only the status at an index through verifyStatus', async () => {
    const cwt = StatusListCwt.fromToken(await token({ statusList: statusList([3]) }))

    // Neither the signature nor the claims are looked at here, so a token for another uri passes
    expect(() => cwt.verifyStatus(0)).not.toThrow()
    expect(() => cwt.verifyStatus(3)).toThrow("Status for id '3' is not Valid")
  })
})
