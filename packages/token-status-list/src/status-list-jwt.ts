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

export type VerifyStatusListJwtClaimsOptions = {
  /** The `uri` of the status list reference the token was fetched for, which `sub` must equal. */
  uri: string
  now?: Date
  /**
   * Clock tolerance applied to `exp`, `nbf` and `iat`, in seconds. Defaults to 30, which keeps a
   * token that only just expired — or was issued a moment ago by a slightly fast clock — usable
   * across the small clock differences typical between issuer and verifier.
   */
  skewSeconds?: number
  /** When false, `iat` is not compared against `now`. Its presence is still required. */
  checkFreshness?: boolean
  /**
   * Require `exp` to be present. It is OPTIONAL in the Token Status List specification, but
   * profiles can make it mandatory — ISO/IEC 18013-5 second edition § 12.3.6.3 does, for the
   * revocation list of an MSO.
   */
  requireExpirationTime?: boolean
}

/**
 * Verify the claims of a Status List Token in JWT format.
 *
 * Both `sub` and `iat` are REQUIRED claims of a Status List Token, and `sub` has to match the URI
 * the token was referenced by — without that check a token published for one URI can be replayed
 * for another under the same issuer.
 *
 * The CWT serialization verifies the same rules through `StatusListCwtPayload.verifyClaims`, which
 * builds on the generic CWT claim verification. A JWT has no such base to build on yet, so the
 * checks are spelled out here.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5
 */
function verifyStatusListJwtClaims(
  payload: StatusListJWTPayload,
  {
    uri,
    now = new Date(),
    skewSeconds = 30,
    checkFreshness = true,
    requireExpirationTime = false,
  }: VerifyStatusListJwtClaimsOptions
): void {
  const skewMs = skewSeconds * 1000
  const secondsToDate = (value: unknown) => (typeof value === 'number' ? new Date(value * 1000) : undefined)

  // The registered JWT claim names, not their CWT counterparts: a Status List Token in JWT format
  // carries `sub`, `iat`, `nbf` and `exp`.
  const subject = typeof payload.sub === 'string' ? payload.sub : undefined
  const issuedAt = secondsToDate(payload.iat)
  const notBefore = secondsToDate(payload.nbf)
  const expirationTime = secondsToDate(payload.exp)

  if (subject === undefined) {
    throw new SLException('The status list token has no subject claim, which is required')
  }

  if (subject !== uri) {
    throw new SLException(`The subject claim '${subject}' must be equal to the uri '${uri}'`)
  }

  if (expirationTime === undefined) {
    if (requireExpirationTime) {
      throw new SLException('The status list token has no expiration claim, which is required for this profile')
    }
    // `exp` is the first instant the token is no longer valid, so a token that expired within the
    // tolerance is still accepted.
  } else if (new Date(expirationTime.getTime() + skewMs) < now) {
    throw new SLException(
      `The expiration claim '${expirationTime.toISOString()}' is in the past (compared to '${now.toISOString()}'), and therefore not valid`
    )
  }

  if (issuedAt === undefined) {
    throw new SLException('The status list token has no issued at claim, which is required')
  }

  if (checkFreshness && new Date(issuedAt.getTime() - skewMs) > now) {
    throw new SLException(
      `The issued at claim '${issuedAt.toISOString()}' is in the future (compared to '${now.toISOString()}'), and therefore not valid`
    )
  }

  if (notBefore !== undefined && new Date(notBefore.getTime() - skewMs) > now) {
    throw new SLException(
      `The not before claim '${notBefore.toISOString()}' is in the future (compared to '${now.toISOString()}'), and therefore not valid`
    )
  }
}

/**
 * Verify the claims of a `token` and the status of an `idx` in it.
 *
 * @todo properly validate the JWT with zod + signature
 */
export function verifyStatus({
  token,
  idx,
  ...claimsOptions
}: { token: string; idx: number } & VerifyStatusListJwtClaimsOptions) {
  const payload = decodeJwtPayload<StatusListJWTPayload>(token)
  const compressed = base64url.decode(payload.status_list.lst)
  const statusList = StatusList.decompressStatusListFromBytes(compressed, payload.status_list.bits)

  verifyStatusListJwtClaims(payload, claimsOptions)

  if (statusList.getStatus(idx) !== StatusType.Valid) {
    throw new SLException(
      `Status for id '${idx}' is not Valid (${StatusType.Valid}), but is instead '${statusList.getStatus(idx)}'`
    )
  }
  return true
}
