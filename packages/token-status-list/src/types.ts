// ==================== Common Types & Constants ====================

/**
 * Status Type values as defined in the spec.
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-7
 */
export enum StatusType {
  /** The status of the Referenced Token is valid, correct or legal. */
  Valid = 0x00,
  /** The status of the Referenced Token is revoked, annulled, taken back, recalled or cancelled. */
  Invalid = 0x01,
  /** The status of the Referenced Token is temporarily invalid, hanging, debarred from privilege. */
  Suspended = 0x02,
  /** Application-specific status (0x03). */
  ApplicationSpecific3 = 0x03,
  /** Application-specific status range start (0x0C). */
  ApplicationSpecificRangeStart = 0x0c,
  /** Application-specific status range end (0x0F). */
  ApplicationSpecificRangeEnd = 0x0f,
}

/**
 * Media types for Status List Tokens
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-14.7
 */
export const MediaTypes = {
  /** Media type for JWT-based Status List Token */
  StatusListJwt: 'application/statuslist+jwt',
  /** Media type for CWT-based Status List Token */
  StatusListCwt: 'application/statuslist+cwt',
} as const

/**
 * BitsPerStatus type.
 */
export type BitsPerStatus = 1 | 2 | 4 | 8

/**
 * Reference to a status list entry.
 */
export interface StatusListEntry {
  idx: number
  uri: string
}
