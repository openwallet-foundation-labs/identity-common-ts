import { describe, expect, it } from 'vitest'
import { StatusList } from '../status-list'
import { StatusListEntryNotValidError, StatusListError } from '../status-list-error'
import { verifyStatusListJwt } from '../status-list-jwt'
import { type BitsPerStatus, StatusType } from '../types'
import { verifyJws } from './context'
import { now, signStatusListToken, statusListClaim, statusListWith, uri } from './status-list-jwt-tokens'

// The status at `idx` in a signed Status List Token, checked by `verifyStatusListJwt`

const verifyStatusAt = async (idx: number | undefined, statusList: StatusList) =>
  verifyStatusListJwt({
    jwt: await signStatusListToken({ status_list: statusListClaim(statusList) }),
    uri,
    now,
    idx,
    verifyJwsCallback: verifyJws,
  })

const expectNotValid = async (verification: Promise<unknown>, idx: number, status: number) => {
  await expect(verification).rejects.toThrow(StatusListEntryNotValidError)
  await expect(verification).rejects.toThrow(`Status for id '${idx}' is not Valid (0), but is instead '${status}'`)
  await expect(verification).rejects.toThrow(StatusListError)
  await expect(verification).rejects.toMatchObject({ idx, status })
}

describe('verifyStatusListJwt with an idx', () => {
  it('accepts a valid status', async () => {
    const { statusList } = await verifyStatusAt(2, statusListWith({ 3: StatusType.Invalid }))

    expect(statusList.getStatus(2)).toBe(StatusType.Valid)
  })

  it('rejects an invalid status', async () => {
    await expectNotValid(verifyStatusAt(3, statusListWith({ 3: StatusType.Invalid })), 3, StatusType.Invalid)
  })

  // 0 is falsy, so a check for a given idx must not be skipped for it
  it('rejects an invalid status at index 0', async () => {
    await expectNotValid(verifyStatusAt(0, statusListWith({ 0: StatusType.Invalid })), 0, StatusType.Invalid)
  })

  it('rejects a suspended status in a list of 2 bits per status', async () => {
    await expectNotValid(verifyStatusAt(4, statusListWith({ 4: StatusType.Suspended }, 2)), 4, StatusType.Suspended)
  })

  it('rejects an application specific status in a list of 4 bits per status', async () => {
    const statusList = statusListWith({ 5: StatusType.ApplicationSpecificRangeStart }, 4)

    await expectNotValid(verifyStatusAt(5, statusList), 5, StatusType.ApplicationSpecificRangeStart)
  })

  it('rejects the largest status of a list of 8 bits per status', async () => {
    await expectNotValid(verifyStatusAt(9, statusListWith({ 9: 255 }, 8)), 9, 255)
  })

  it.each([1, 2, 4, 8] as const)(
    'accepts the valid neighbours of the largest status in a list of %i bits per status',
    async (bits: BitsPerStatus) => {
      const statusList = statusListWith({ 4: 2 ** bits - 1 }, bits)

      const [before, after] = await Promise.all([verifyStatusAt(3, statusList), verifyStatusAt(5, statusList)])

      expect([before.statusList.getStatus(3), after.statusList.getStatus(5)]).toEqual([
        StatusType.Valid,
        StatusType.Valid,
      ])
    }
  )

  it('does not check any status without an idx', async () => {
    const { statusList } = await verifyStatusAt(undefined, statusListWith({ 0: StatusType.Invalid }))

    expect(statusList.getStatus(0)).toBe(StatusType.Invalid)
  })

  // The list is carried in whole bytes, see "Known limitation" in the README
  it('accepts an idx in the unused bits of the last byte of the list', async () => {
    const { statusList } = await verifyStatusAt(7, new StatusList([StatusType.Invalid, 0, 0], 1))

    expect(statusList.getStatus(7)).toBe(StatusType.Valid)
  })

  it('rejects an idx beyond the end of the list', async () => {
    await expect(verifyStatusAt(16, statusListWith())).rejects.toThrow('Index out of bounds')
  })
})
