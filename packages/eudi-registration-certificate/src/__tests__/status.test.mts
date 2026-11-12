import { StatusListMediaTypes } from '@owf/token-status-list'
import { describe, expect, it, vi } from 'vitest'
import {
  RegistrationCertificateValidationError,
  type VerifyRegistrationCertificateCallbacks,
  type VerifyRegistrationCertificateStatusOptions,
  verifyRegistrationCertificateStatus,
  zStatus,
} from '../index'
import { callbacks, STATUS_LIST_URI, servedAs, statusListCwt, statusListJwt } from './context.mjs'

const now = new Date()
const iat = Math.floor(now.getTime() / 1000)

const verify = (
  idx: number,
  fetch: typeof globalThis.fetch,
  overrides: Partial<VerifyRegistrationCertificateCallbacks> = {},
  at = now,
  limits: Pick<VerifyRegistrationCertificateStatusOptions, 'maxResponseBytes' | 'maxDecompressedBytes'> = {}
) =>
  verifyRegistrationCertificateStatus({
    status: { status_list: { idx, uri: STATUS_LIST_URI } },
    callbacks: { ...callbacks, fetch, ...overrides },
    now: at,
    ...limits,
  })

describe('verifyRegistrationCertificateStatus', () => {
  describe.each([
    ['JWT', async () => servedAs(await statusListJwt({ iat }), StatusListMediaTypes.StatusListJwt)],
    ['CWT', async () => servedAs(await statusListCwt({ iat }), StatusListMediaTypes.StatusListCwt)],
  ])('with a status list in %s format', (_, fetch) => {
    it('accepts a valid registration certificate', async () => {
      await expect(verify(0, await fetch())).resolves.toBeUndefined()
    })

    it('rejects a revoked registration certificate', async () => {
      const error = await verify(1, await fetch()).catch((error) => error)

      expect(error).toBeInstanceOf(RegistrationCertificateValidationError)
      expect(error.findIssue('revoked')).toMatchObject({
        path: ['status_list', 'idx'],
        requirement: 'REV-6.2.6.2-04',
        context: { status: 1 },
      })
    })

    it('rejects a status list whose signature does not verify', async () => {
      const overrides = { verifyJws: () => ({ verified: false as const }), verifyCose: () => false }

      const error = await verify(0, await fetch(), overrides).catch((error) => error)

      expect(error.findIssue('invalid_status_list')).toMatchObject({ path: ['status_list', 'uri'] })
    })

    it('rejects a status list issued after now', async () => {
      await expect(verify(0, await fetch(), {}, new Date((iat - 3600) * 1000))).rejects.toThrow('in the future')
    })

    // The list of four statuses of 1 bit inflates to one byte
    it('rejects a status list that inflates to more than maxDecompressedBytes', async () => {
      const error = await verify(0, await fetch(), {}, now, { maxDecompressedBytes: 0 }).catch((error) => error)

      expect(error.findIssue('invalid_status_list')).toMatchObject({ path: ['status_list', 'uri'] })
      expect(error.findIssue('invalid_status_list').message).toContain('larger than the maximum of 0 bytes')
    })

    // The signed token is far larger than 100 bytes
    it('reports a status list response larger than maxResponseBytes', async () => {
      const error = await verify(0, await fetch(), {}, now, { maxResponseBytes: 100 }).catch((error) => error)

      expect(error.findIssue('status_list_unavailable')).toMatchObject({ path: ['status_list', 'uri'] })
      expect(error.findIssue('status_list_unavailable').message).toContain('larger than the maximum of 100 bytes')
    })

    it('rejects an index outside the status list', async () => {
      await expect(verify(1000, await fetch())).rejects.toThrow(RegistrationCertificateValidationError)
    })
  })

  it('reports a status list that cannot be fetched', async () => {
    const unavailable: typeof fetch = async () => new Response('', { status: 503 })

    const error = await verify(0, unavailable).catch((error) => error)

    expect(error.findIssue('status_list_unavailable')).toMatchObject({ path: ['status_list', 'uri'] })
  })

  it('rejects a status list for another uri', async () => {
    const fetch = servedAs(
      await statusListJwt({ iat, sub: `${STATUS_LIST_URI}/other` }),
      StatusListMediaTypes.StatusListJwt
    )

    await expect(verify(0, fetch)).rejects.toThrow(RegistrationCertificateValidationError)
  })

  it('rejects a JWT that is not a status list before verifying its signature', async () => {
    const verifyJws = vi.fn(callbacks.verifyJws)
    const fetch = servedAs(await statusListJwt({ iat, typ: 'rc-wrp+jwt' }), StatusListMediaTypes.StatusListJwt)

    await expect(verify(0, fetch, { verifyJws })).rejects.toThrow(RegistrationCertificateValidationError)
    expect(verifyJws).not.toHaveBeenCalled()
  })

  it('reads idx as the numeric string of GEN-6.2.6.1-04', () => {
    const status = zStatus.parse({ status_list: { idx: '1', uri: STATUS_LIST_URI } })

    expect(status.status_list.idx).toBe(1)
    expect(() => zStatus.parse({ status_list: { idx: '-1', uri: STATUS_LIST_URI } })).toThrow()
    expect(() => zStatus.parse({ status_list: { idx: '1.5', uri: STATUS_LIST_URI } })).toThrow()
  })
})
