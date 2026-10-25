/**
 *
 * A NumericDate (seconds since the epoch, RFC 7519) relative to now.
 *
 */
export const numericDate = (offsetMs = 0) => Math.floor((Date.now() + offsetMs) / 1000)
