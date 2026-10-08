import { zNumericDate } from '@owf/identity-common'
import { zBase64Url, zJoseType, zJwtHeader, zJwtPayload } from '@owf/jose'
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

/** The number of bits per status, which the spec limits to these four values. */
export const zBitsPerStatus = z.union([z.literal(1), z.literal(2), z.literal(4), z.literal(8)])

/**
 * A reference to an entry in a status list.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-7.1
 */
export const zStatusListEntry = z
  .object({
    idx: z.number().int().nonnegative(),
    uri: z.string(),
  })
  .loose()

/**
 * The payload of a JWT that references a status list, which is any token whose status can be looked
 * up — a credential, typically.
 */
export const zJwtWithStatusListPayload = z
  .object({
    ...zJwtPayload.shape,
    status: z
      .object({
        status_list: zStatusListEntry,
      })
      .loose(),
  })
  .loose()

export type JwtWithStatusListPayload = z.infer<typeof zJwtWithStatusListPayload>

/**
 * The payload of a Status List Token in JWT format.
 *
 * `sub` and `iat` are required: a Status List Token that does not say which uri it was published for
 * could be replayed for another list of the same issuer, and one that does not say when it was
 * issued cannot be checked for freshness.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5.1
 */
export const zStatusListJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    sub: z.string(),
    iat: zNumericDate,
    ttl: z.number().optional(),
    status_list: z
      .object({
        bits: zBitsPerStatus,
        lst: zBase64Url,
        aggregation_uri: z.string().optional(),
      })
      .loose(),
  })
  .loose()

export type StatusListJwtPayload = z.infer<typeof zStatusListJwtPayload>

/**
 * The header of a Status List Token in JWT format. Its `typ` is what distinguishes it from any other
 * token signed by the same issuer, so it is required and must be `statuslist+jwt`.
 *
 * The `typ` is compared as a media type, so `application/statuslist+jwt` is accepted too: RFC 7515
 * section 4.1.9 lets a producer omit the `application/` prefix, and requires a recipient to treat a
 * value without a `/` as if the prefix were present.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5.1
 */
export const zStatusListJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: zJoseType(JWT_STATUS_LIST_TYPE),
  })
  .loose()

export type StatusListJwtHeaderParameters = z.infer<typeof zStatusListJwtHeader>
