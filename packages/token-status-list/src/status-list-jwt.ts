import type { JwtPayload } from '@owf/identity-common'
import { base64url, bytesToString } from '@owf/identity-common'
import type { JWTwithStatusListPayload, StatusListJWTHeaderParameters, StatusListJWTPayload } from './jwt-types'
import { JWT_STATUS_LIST_TYPE } from './jwt-types'
import { StatusList } from './status-list'
import { SLException } from './status-list-exception'
import { type StatusListEntry, StatusType } from './types'
import { verifyStatusListClaims } from './verify-status-list-claims'

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
 * Verify the status of an `idx` in a `token`.
 *
 * The claim checks are shared with the CWT serialization through
 * {@link verifyStatusListClaims}, so both stay in step.
 *
 * @todo properly validate the JWT with zod + signature
 */
export function verifyStatus({
  uri,
  idx,
  token,
  checkFreshness,
  now,
  skewSeconds,
  requireExpirationTime,
}: {
  token: string
  idx: number
  uri: string
  checkFreshness?: boolean
  now?: Date
  /** Clock tolerance applied to `exp` and `iat`, in seconds. Defaults to 30. */
  skewSeconds?: number
  /** Require `exp`, which is OPTIONAL by default. */
  requireExpirationTime?: boolean
}) {
  const payload = decodeJwtPayload<StatusListJWTPayload>(token)
  const compressed = base64url.decode(payload.status_list.lst)
  const statusList = StatusList.decompressStatusListFromBytes(compressed, payload.status_list.bits)

  verifyStatusListClaims({
    claims: {
      // The registered JWT claim names, not their CWT counterparts: a Status List Token in
      // JWT format carries `sub`, `iat` and `exp`.
      subject: typeof payload.sub === 'string' ? payload.sub : undefined,
      issuedAt: typeof payload.iat === 'number' ? new Date(payload.iat * 1000) : undefined,
      expirationTime: typeof payload.exp === 'number' ? new Date(payload.exp * 1000) : undefined,
    },
    uri,
    now,
    skewSeconds,
    checkFreshness,
    requireExpirationTime,
  })

  if (statusList.getStatus(idx) !== StatusType.Valid) {
    throw new SLException(
      `Status for id '${idx}' is not Valid (${StatusType.Valid}), but is instead '${statusList.getStatus(idx)}'`
    )
  }
  return true
}
