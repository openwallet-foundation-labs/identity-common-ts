import { zBase64Url, zNonEmptyString, zNumericDate, zTyp } from '@owf/identity-common'
import { zJwtHeader, zJwtPayload } from '@owf/jose'
import z from 'zod'

// ==================== JWT Types & Constants ====================

/**
 * JWT type header value for Status List Token
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5.1
 */
export const JWT_STATUS_LIST_TYPE = 'statuslist+jwt'

/**
 * JWT claim names for Status List
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-14.1
 */
export const JwtClaimNames = {
  STATUS: 'status',
  STATUS_LIST: 'status_list',
  TTL: 'ttl',
  IDX: 'idx',
  URI: 'uri',
  BITS: 'bits',
  LST: 'lst',
  AGGREGATION_URI: 'aggregation_uri',
} as const

export const zBitsPerStatus = z.union([z.literal(1), z.literal(2), z.literal(4), z.literal(8)])

/**
 * The `status_list` member of the `status` claim: the index and uri of a Referenced Token's status.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-6.2
 */
export const zStatusListReference = z
  .object({
    idx: z.number().int().nonnegative(),
    uri: zNonEmptyString,
  })
  .loose()

export type StatusListReference = z.infer<typeof zStatusListReference>

/** The `status` claim of a Referenced Token, to add to the payload schema of a token. */
export const zStatusClaim = z.object({ status_list: zStatusListReference }).loose()

export type StatusClaim = z.infer<typeof zStatusClaim>

/** The payload of a Referenced Token in JWT format. */
export const zReferencedTokenJwtPayload = z.object({ ...zJwtPayload.shape, status: zStatusClaim }).loose()

export type ReferencedTokenJwtPayload = z.infer<typeof zReferencedTokenJwtPayload>

/** @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5.1 */
export const zStatusListJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    sub: zNonEmptyString,
    iat: zNumericDate,
    // Draft 16 § 5.1: "MUST be a positive number"
    ttl: z.number().positive().optional(),
    status_list: z
      .object({
        bits: zBitsPerStatus,
        lst: zBase64Url,
        aggregation_uri: zNonEmptyString.optional(),
      })
      .loose(),
  })
  .loose()

export type StatusListJwtPayload = z.infer<typeof zStatusListJwtPayload>

/** @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5.1 */
export const zStatusListJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: zTyp(JWT_STATUS_LIST_TYPE),
  })
  .loose()

export type StatusListJwtHeaderParameters = z.infer<typeof zStatusListJwtHeader>
