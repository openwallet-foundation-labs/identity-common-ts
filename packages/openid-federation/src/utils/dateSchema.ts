import { z } from 'zod'

/**
 *
 * NumericDate (RFC 7519 Section 2): seconds since the epoch, parsed to a js date object
 *
 */
export const dateSchema = z.number().transform((seconds) => new Date(seconds * 1000))
