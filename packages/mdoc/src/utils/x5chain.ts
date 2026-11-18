import { HashAlgorithm } from '@owf/cose'
import type { MdocContext } from '../context'

/**
 * The value of an `x5chain` COSE header (RFC 9360): a single certificate as a byte string, and a
 * chain of more than one certificate as an array, as in the examples of 18013-5 Annex D.
 */
export const x5chainHeaderValue = (certificateChain: Array<Uint8Array>): Uint8Array | Array<Uint8Array> =>
  certificateChain.length === 1 ? certificateChain[0] : certificateChain

/**
 * The value of a protected `x5t` COSE header (RFC 9360) for the leaf of a certificate chain, with
 * SHA-256 as 18013-5 (second edition) 12.3.4 and 12.5.4 require.
 */
export const x5tHeaderValue = async (certificateChain: Array<Uint8Array>, ctx: Pick<MdocContext, 'crypto'>) => [
  HashAlgorithm.SHA256,
  await ctx.crypto.digest({ digestAlgorithm: 'SHA-256', bytes: certificateChain[0] }),
]
