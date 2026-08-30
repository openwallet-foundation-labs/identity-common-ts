import { SLException } from './status-list-exception'

/**
 * The claims a Status List Token carries, normalized across its two serializations:
 * the JWT claims `sub` / `iat` / `exp` and their CWT counterparts (labels 2, 6 and 4).
 */
export type StatusListClaims = {
  subject?: string
  issuedAt?: Date
  expirationTime?: Date
}

export type VerifyStatusListClaimsOptions = {
  claims: StatusListClaims
  /** The `uri` of the status list reference the token was fetched for. */
  uri: string
  now?: Date
  /**
   * Clock tolerance applied to `exp` and `iat`, in seconds. Defaults to 30, which keeps a
   * token that only just expired — or was issued a moment ago by a slightly fast clock —
   * usable across the small clock differences typical between issuer and verifier.
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
 * Verify the claims of a Status List Token, independent of its serialization and of how its
 * signature was checked.
 *
 * Both `sub` and `iat` are REQUIRED claims of a Status List Token, and `sub` has to match the
 * URI the token was referenced by — without that check a token published for one URI can be
 * replayed for another under the same issuer.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5
 */
export function verifyStatusListClaims({
  claims,
  uri,
  now = new Date(),
  skewSeconds = 30,
  checkFreshness = true,
  requireExpirationTime = false,
}: VerifyStatusListClaimsOptions): void {
  const skewMs = skewSeconds * 1000

  if (claims.subject === undefined) {
    throw new SLException('The status list token has no subject claim, which is required')
  }

  if (claims.subject !== uri) {
    throw new SLException(`The subject claim '${claims.subject}' must be equal to the uri '${uri}'`)
  }

  if (claims.expirationTime === undefined) {
    if (requireExpirationTime) {
      throw new SLException('The status list token has no expiration claim, which is required for this profile')
    }
  } else if (new Date(claims.expirationTime.getTime() + skewMs) < now) {
    throw new SLException(
      `The expiration claim '${claims.expirationTime.toISOString()}' is in the past (compared to '${now.toISOString()}'), and therefore not valid`
    )
  }

  if (claims.issuedAt === undefined) {
    throw new SLException('The status list token has no issued at claim, which is required')
  }

  if (checkFreshness && new Date(claims.issuedAt.getTime() - skewMs) > now) {
    throw new SLException(
      `The issued at claim '${claims.issuedAt.toISOString()}' is in the future (compared to '${now.toISOString()}'), and therefore not valid`
    )
  }
}
