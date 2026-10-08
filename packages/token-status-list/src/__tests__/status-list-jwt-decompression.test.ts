import { base64url } from '@owf/identity-common'
import { JoseClaimVerificationError, JoseSignatureVerificationError, JoseValidationError } from '@owf/jose'
import { deflate } from 'pako'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { StatusList } from '../status-list'
import { StatusListEntryNotValidError, StatusListError } from '../status-list-error'
import { decodeStatusListJwt, verifyStatusListJwt } from '../status-list-jwt'
import { StatusType } from '../types'
import { verifyJws } from './context'
import {
  notCompressedLst,
  now,
  signStatusListToken,
  statusListClaim,
  statusListWith,
  uri,
  withInvalidSignature,
} from './status-list-jwt-tokens'

// `lst` is compressed, so a few kilobytes of it can inflate to a list of any size. It is only the
// issuer's once the signature over it verifies, so nothing may decompress it before that.

// One MiB of zero bytes, a list of 8 388 608 valid statuses, compresses to about a kilobyte
const largeListLst = base64url.encode(deflate(new Uint8Array(1024 * 1024), { level: 9 }))

afterEach(() => {
  vi.restoreAllMocks()
})

describe('verifyStatusListJwt', () => {
  it('rejects a token whose signature does not verify before decompressing its status list', async () => {
    const jwt = await withInvalidSignature(
      await signStatusListToken({ status_list: { bits: 1, lst: notCompressedLst } })
    )

    await expect(verifyStatusListJwt({ jwt, uri, now, verifyJwsCallback: verifyJws })).rejects.toThrow(
      JoseSignatureVerificationError
    )
  })

  it('does not decompress a large status list whose signature does not verify', async () => {
    const decompress = vi.spyOn(StatusList, 'decompressStatusListFromBytes')
    const jwt = await withInvalidSignature(await signStatusListToken({ status_list: { bits: 1, lst: largeListLst } }))

    await expect(verifyStatusListJwt({ jwt, uri, now, verifyJwsCallback: verifyJws })).rejects.toThrow(
      JoseSignatureVerificationError
    )
    expect(decompress).not.toHaveBeenCalled()
  })

  // What a verifier that has to look at the token first does: decode, then verify the decoded token
  it('rejects a decoded token whose signature does not verify before decompressing its status list', async () => {
    const decoded = decodeStatusListJwt(
      await withInvalidSignature(await signStatusListToken({ status_list: { bits: 1, lst: notCompressedLst } }))
    )

    await expect(verifyStatusListJwt({ jwt: decoded, uri, now, verifyJwsCallback: verifyJws })).rejects.toThrow(
      JoseSignatureVerificationError
    )
  })

  it('rejects a token whose claims do not verify before decompressing its status list', async () => {
    const jwt = await signStatusListToken({ status_list: { bits: 1, lst: notCompressedLst } })

    const verification = verifyStatusListJwt({
      jwt,
      uri: 'https://example.com/other',
      now,
      verifyJwsCallback: verifyJws,
    })

    await expect(verification).rejects.toThrow(JoseClaimVerificationError)
    await expect(verification).rejects.toMatchObject({ claim: 'sub', reason: 'mismatch' })
  })

  it('rejects a token that is not a status list token before decompressing its status list', async () => {
    const jwt = await signStatusListToken({ status_list: { bits: 1, lst: notCompressedLst } }, { typ: 'JWT' })

    const verification = verifyStatusListJwt({ jwt, uri, now, verifyJwsCallback: verifyJws })

    await expect(verification).rejects.toThrow(JoseValidationError)
    await expect(verification).rejects.toThrow('at "typ"')
  })

  it('rejects a verified token whose status list cannot be decompressed', async () => {
    const jwt = await signStatusListToken({ status_list: { bits: 1, lst: notCompressedLst } })

    const verification = verifyStatusListJwt({ jwt, uri, now, verifyJwsCallback: verifyJws })

    await expect(verification).rejects.toThrow(StatusListError)
    await expect(verification).rejects.toThrow('The status list token has no valid status_list claim')
    await expect(verification).rejects.not.toThrow(StatusListEntryNotValidError)
  })
})

describe('decodeStatusListJwt', () => {
  it('decodes the header and claims of a token without decompressing its status list', async () => {
    const decompress = vi.spyOn(StatusList, 'decompressStatusListFromBytes')
    const jwt = await signStatusListToken({ status_list: { bits: 1, lst: largeListLst } })

    const { payload } = decodeStatusListJwt(jwt)

    expect(payload.status_list).toEqual({ bits: 1, lst: largeListLst })
    expect(decompress).not.toHaveBeenCalled()
  })

  it('decodes a token whose status list cannot be decompressed', async () => {
    const jwt = await signStatusListToken({ status_list: { bits: 1, lst: notCompressedLst } })

    expect(decodeStatusListJwt(jwt).payload.sub).toBe(uri)
  })

  it('decompresses the status list when it is first read', async () => {
    const decoded = decodeStatusListJwt(await signStatusListToken({ status_list: { bits: 1, lst: notCompressedLst } }))

    expect(() => decoded.statusList).toThrow(StatusListError)
    expect(() => decoded.statusList).toThrow('The status list token has no valid status_list claim')
  })

  it('returns the same status list every time it is read', async () => {
    const decoded = decodeStatusListJwt(await signStatusListToken())

    expect(decoded.statusList).toBe(decoded.statusList)
  })

  it('decompresses the status list of the token as it was decoded, even once the decoded claims changed', async () => {
    const decoded = decodeStatusListJwt(
      await signStatusListToken({ status_list: statusListClaim(statusListWith({ 3: StatusType.Invalid })) })
    )

    decoded.payload.status_list = statusListClaim(statusListWith())

    expect(decoded.statusList.getStatus(3)).toBe(StatusType.Invalid)
  })

  it('reads the statuses carried in the token', async () => {
    const decoded = decodeStatusListJwt(
      await signStatusListToken({ status_list: statusListClaim(statusListWith({ 3: StatusType.Invalid })) })
    )

    expect(decoded.statusList.statusList.slice(0, 5)).toEqual([0, 0, 0, 1, 0])
  })
})
