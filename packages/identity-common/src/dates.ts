/**
 * Conversions between JavaScript `Date` values and the Unix timestamps in seconds
 * used by JWT, CWT and COSE claims such as `iat`, `exp` and `nbf`.
 */

/**
 * Convert a `Date` to a Unix timestamp in seconds, truncating sub-second precision.
 */
export const dateToSeconds = (date: Date): number => Math.floor(date.getTime() / 1000)

/**
 * Convert a Unix timestamp in seconds to a `Date`.
 */
export const secondsToDate = (seconds: number): Date => new Date(seconds * 1000)

/**
 * The current time as a Unix timestamp in seconds.
 */
export const nowInSeconds = (): number => dateToSeconds(new Date())
