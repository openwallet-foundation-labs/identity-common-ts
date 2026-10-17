import { z } from 'zod'

const MIN_SAFE = BigInt(Number.MIN_SAFE_INTEGER)
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER)

/**
 * An integer as cbor-x decodes it: a number, or a bigint when the encoder wrote it in 8 bytes,
 * whatever its value. Only values a number holds exactly are accepted; read them with `Number()`.
 */
export const zInteger = z.union([z.number().int(), z.bigint().min(MIN_SAFE).max(MAX_SAFE)])

/**
 * A non-negative {@link zInteger}, a CDDL `uint`.
 */
export const zUnsignedInteger = z.union([z.number().int().nonnegative(), z.bigint().nonnegative().max(MAX_SAFE)])
