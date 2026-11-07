import { base64url } from '@owf/identity-common'
import { signJwt } from '@owf/jose'
import { JWT_STATUS_LIST_TYPE } from '../jwt-types'
import { StatusList } from '../status-list'
import { type BitsPerStatus, StatusType } from '../types'
import { jwsSigner, signJws } from './context'

export const uri = 'https://example.com/statuslists/1'

/** The time the tokens of a test are verified at, so that the time claims can be set relative to it. */
export const now = new Date('2026-01-01T12:00:00.000Z')

/** `now`, shifted by `offset` seconds, as a NumericDate. */
export const secondsFromNow = (offset: number) => Math.floor(now.getTime() / 1000) + offset

/** A list of ten statuses, `Valid` except for the ones given. */
export const statusListWith = (statuses: Record<number, number> = {}, bits: BitsPerStatus = 1) => {
  const list = new StatusList(new Array(10).fill(StatusType.Valid), bits)
  for (const [index, status] of Object.entries(statuses)) list.setStatus(Number(index), status)
  return list
}

/** The `status_list` claim carrying `list`. */
export const statusListClaim = (list: StatusList) => ({
  bits: list.getBitsPerStatus(),
  lst: base64url.encode(list.compressStatusListToBytes()),
})

/** An `lst` that is valid base64url, but not a compressed status list: no zlib stream starts with `00 00`. */
export const notCompressedLst = 'AAAA'

/**
 * Signs a Status List Token with the key of `context.ts`, verified by its `verifyJws`.
 *
 * Unlike `signStatusListJwt` the claims are signed as given, so that a token can carry an `lst` that
 * is not a compressed status list. They default to the claims of a conformant token, issued a minute
 * before `now`, carrying the list of {@link statusListWith}; set one to `undefined` to drop it.
 */
export const signStatusListToken = async (
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {}
) => {
  const { jwt } = await signJwt({
    header: { typ: JWT_STATUS_LIST_TYPE, ...header },
    payload: { sub: uri, iat: secondsFromNow(-60), status_list: statusListClaim(statusListWith()), ...claims },
    signer: jwsSigner,
    signJwsCallback: signJws,
  })

  return jwt
}

/**
 * `jwt` with its signature replaced by one that does not verify over it: a signature made with the
 * same key, but over another token.
 */
export const withInvalidSignature = async (jwt: string) => {
  const [header, payload] = jwt.split('.')
  const [, , otherSignature] = (await signStatusListToken({ sub: 'https://example.com/other' })).split('.')

  return `${header}.${payload}.${otherSignature}`
}
