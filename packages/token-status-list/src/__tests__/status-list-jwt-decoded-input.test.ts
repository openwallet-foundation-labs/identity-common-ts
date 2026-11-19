import { JoseSignatureVerificationError, JoseValidationError } from '@owf/jose'
import { describe, expect, it } from 'vitest'
import { decodeStatusListJwt, verifyStatusListJwt } from '../status-list-jwt'
import { StatusType } from '../types'
import { claimIssue, statusListIssue, verifyJws } from './context'
import {
  now,
  signStatusListToken,
  statusListClaim,
  statusListWith,
  uri,
  withInvalidSignature,
} from './status-list-jwt-tokens'

// `verifyStatusListJwt` verifies a decoded token without decoding it again, and inflates the list itself

// A token whose status at index 3 is not valid
const decodedToken = async () =>
  decodeStatusListJwt(
    await signStatusListToken({ status_list: statusListClaim(statusListWith({ 3: StatusType.Invalid })) })
  )

describe('verifyStatusListJwt with a decoded token', () => {
  it('checks the status at idx in the signed list, not in a list put on the decoded token', async () => {
    const decoded = { ...(await decodedToken()), statusList: statusListWith() }

    const verification = verifyStatusListJwt({ jwt: decoded, uri, now, idx: 3, verifyJwsCallback: verifyJws })

    await expect(verification).rejects.toEqual(statusListIssue('status_not_valid', { idx: 3, status: 1 }))
    await expect(verification).rejects.toThrow("Status for id '3' is not Valid (0), but is instead '1'")
  })

  it('returns the signed list rather than a list put on the decoded token', async () => {
    const decoded = { ...(await decodedToken()), statusList: statusListWith() }

    const { statusList } = await verifyStatusListJwt({ jwt: decoded, uri, now, verifyJwsCallback: verifyJws })

    expect(statusList.getStatus(3)).toBe(StatusType.Invalid)
  })

  it('verifies the signed claims, not claims changed on the decoded token', async () => {
    const decoded = await decodedToken()
    const changed = { ...decoded, payload: { ...decoded.payload, sub: 'https://example.com/other' } }

    const verification = verifyStatusListJwt({
      jwt: changed,
      uri: 'https://example.com/other',
      now,
      verifyJwsCallback: verifyJws,
    })

    await expect(verification).rejects.toThrow(JoseValidationError)
    await expect(verification).rejects.toEqual(claimIssue('sub', 'claim_value_mismatch'))
  })

  it('verifies what decodeStatusListJwt returned, with the limit given to it', async () => {
    const decoded = await decodedToken()

    const { payload, statusList } = await verifyStatusListJwt({ jwt: decoded, uri, now, verifyJwsCallback: verifyJws })
    expect(payload).toBe(decoded.payload)
    expect(statusList.getStatus(3)).toBe(StatusType.Invalid)

    await expect(
      verifyStatusListJwt({ jwt: decoded, uri, now, verifyJwsCallback: verifyJws, maxDecompressedBytes: 0 })
    ).rejects.toThrow('larger than the maximum of 0 bytes')
  })

  it('verifies the signature of a decoded token', async () => {
    const decoded = decodeStatusListJwt(await withInvalidSignature((await decodedToken()).compact))

    await expect(verifyStatusListJwt({ jwt: decoded, uri, now, verifyJwsCallback: verifyJws })).rejects.toThrow(
      JoseSignatureVerificationError
    )
  })
})
