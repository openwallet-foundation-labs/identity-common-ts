import type { JwtPayload } from '@owf/identity-common'
import { base64url, bytesToString } from '@owf/identity-common'
import type { JWTwithStatusListPayload, StatusListJWTHeaderParameters, StatusListJWTPayload } from './jwt-types'
import { JWT_STATUS_LIST_TYPE } from './jwt-types'
import { StatusList } from './status-list'
import { SLException } from './status-list-exception'
import { type StatusListEntry, StatusType } from './types'

/**
 * Decode a JWT and return the payload.
 * @param jwt JWT token in compact JWS serialization.
 */
function decodeJwtPayload<T>(jwt: string): T {
  const parts = jwt.split('.')
  return JSON.parse(bytesToString(base64url.decode(parts[1])))
}

/**
 * Adds the status list to the payload and header of a JWT.
 */
export function createHeaderAndPayload(list: StatusList, payload: JwtPayload, header: StatusListJWTHeaderParameters) {
  if (!payload.sub) {
    throw new SLException('sub field is required')
  }
  if (!payload.iat) {
    throw new SLException('iat field is required')
  }

  header.typ = JWT_STATUS_LIST_TYPE
  payload.status_list = {
    bits: list.getBitsPerStatus(),
    lst: base64url.encode(list.compressStatusListToBytes()),
  }
  return { header, payload }
}

/**
 * Get the status list from a JWT, but do not verify the signature.
 */
export function getListFromStatusListJWT(jwt: string): StatusList {
  const payload = decodeJwtPayload<StatusListJWTPayload>(jwt)
  const statusList = payload.status_list
  const compressed = base64url.decode(statusList.lst)
  return StatusList.decompressStatusListFromBytes(compressed, statusList.bits)
}

/**
 * Get the status list entry from a JWT, but do not verify the signature.
 */
export function getStatusListFromJWT(jwt: string): StatusListEntry {
  const payload = decodeJwtPayload<JWTwithStatusListPayload>(jwt)
  return payload.status.status_list
}

/**
 * Verify the status of an `idx` in a `token`
 *
 * @todo properly validate the JWT with zod + signature
 */
export function verifyStatus({
  uri,
  idx,
  token,
  checkFreshness = true,
  now = new Date(),
}: {
  token: string
  idx: number
  uri: string
  checkFreshness?: boolean
  now?: Date
}) {
  const payload = decodeJwtPayload<StatusListJWTPayload>(token)
  const compressed = base64url.decode(payload.status_list.lst)
  const statusList = StatusList.decompressStatusListFromBytes(compressed, payload.status_list.bits)
  if (payload.subject !== uri) {
    throw new SLException(`The subject claim '${payload.subject}' must be equal to the uri '${uri}'`)
  }
  if (checkFreshness && payload.iat && payload.iat > Math.floor(now.getTime() / 1000)) {
    throw new SLException(
      `The issued at claim '${payload.issuedAt}' is in the future (compared to '${now}'), and therefore not valid`
    )
  }
  if (payload.exp && payload.exp < Math.floor(now.getTime() / 1000)) {
    throw new SLException(
      `The expiry claim '${payload.exp}' is in the past (compared to '${now}'), and therefore not valid`
    )
  }
  if (statusList.getStatus(idx) !== StatusType.Valid) {
    throw new SLException(
      `Status for id '${idx}' is not Valid (${StatusType.Valid}), but is instead '${statusList.getStatus(idx)}'`
    )
  }
  return true
}
