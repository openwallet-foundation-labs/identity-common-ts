import type { JwtPayload } from '@owf/identity-common'
import type { BitsPerStatus, StatusListEntry } from './types'

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

/**
 * Payload for a JWT with a status reference.
 */
export interface JwtWithStatusListPayload extends JwtPayload {
  status: {
    status_list: StatusListEntry
  }
}

/**
 * Payload for a Status List JWT.
 */
export interface StatusListJwtPayload extends JwtPayload {
  ttl?: number
  status_list: {
    bits: BitsPerStatus
    lst: string
  }
}

/**
 * Header parameters for a JWT Status List Token.
 */
export type StatusListJwtHeaderParameters = {
  alg: string
  typ: typeof JWT_STATUS_LIST_TYPE
  [key: string]: unknown
}
