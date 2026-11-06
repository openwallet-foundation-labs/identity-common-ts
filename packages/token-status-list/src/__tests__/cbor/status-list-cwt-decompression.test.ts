import {
  CoseInvalidSignatureError,
  cborEncode,
  RegisteredCwtClaimKey,
  RegisteredCwtHeaderClaimKey,
  Sign1,
  SignatureAlgorithm,
} from '@owf/cose'
import { describe, expect, test } from 'vitest'
import { StatusListCwt } from '../../cbor/status-list-cwt'
import { StatusListCwtClaimKey } from '../../cbor/status-list-cwt-payload'
import { StatusListError } from '../../status-list-error'
import { StatusListMediaTypes } from '../../types'
import { otherSignKey, sign1Context, signKey, statusListIssue } from '../context'

// `lst` is only decompressed once the signature verified, as in status-list-jwt-decompression.test.ts

const uri = 'https://example.com/statuslists/1'
const now = new Date('2026-01-01T12:00:00.000Z')
const nowInSeconds = now.getTime() / 1000

/**
 * A status list CWT signed with `signKey`, built from the COSE primitives so that `lst` can be bytes
 * that are not a compressed status list: the status list classes would not create one.
 */
const signedToken = async ({ lst }: { lst: Uint8Array }) => {
  const claims = new Map<number, unknown>([
    [RegisteredCwtClaimKey.Subject, uri],
    [RegisteredCwtClaimKey.IssuedAt, nowInSeconds - 60],
    [
      StatusListCwtClaimKey.StatusList,
      new Map<string, unknown>([
        ['bits', 1],
        ['lst', lst],
      ]),
    ],
  ])

  const sign1 = await Sign1.create({
    protectedHeaders: new Map<number, unknown>([
      [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
      [RegisteredCwtHeaderClaimKey.Typ, StatusListMediaTypes.StatusListCwt],
    ]),
    payload: cborEncode(claims),
  }).sign({ signingKey: signKey, algorithm: SignatureAlgorithm.ES256 }, sign1Context)

  return sign1.encode()
}

// No zlib stream starts with `00 00`
const notCompressedLst = new Uint8Array([0, 0, 0])

describe('StatusListCwt', () => {
  test('decodes a token whose status list cannot be decompressed', async () => {
    const cwt = StatusListCwt.fromToken(await signedToken({ lst: notCompressedLst }))

    expect(cwt.payload.subject).toBe(uri)
  })

  test('rejects a token whose signature does not verify before decompressing its status list', async () => {
    const cwt = StatusListCwt.fromToken(await signedToken({ lst: notCompressedLst }))

    await expect(cwt.verify({ key: otherSignKey, uri, now, idx: 0 }, { sign1: sign1Context })).rejects.toThrow(
      CoseInvalidSignatureError
    )
  })

  test('rejects a token whose claims do not verify before decompressing its status list', async () => {
    const cwt = StatusListCwt.fromToken(await signedToken({ lst: notCompressedLst }))

    const verification = cwt.verify(
      { key: signKey, uri: 'https://example.com/other', now, idx: 0 },
      { sign1: sign1Context }
    )
    await expect(verification).rejects.toThrow(StatusListError)
    await expect(verification).rejects.toThrow("Status list token claim verification failed. The 'Subject (2)' claim")
  })

  test('rejects a verified token whose status list cannot be decompressed', async () => {
    const cwt = StatusListCwt.fromToken(await signedToken({ lst: notCompressedLst }))

    await expect(cwt.verify({ key: signKey, uri, now, idx: 0 }, { sign1: sign1Context })).rejects.toEqual(
      statusListIssue('invalid_status_list')
    )
  })
})
