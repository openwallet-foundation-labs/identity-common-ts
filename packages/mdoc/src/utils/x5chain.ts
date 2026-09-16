/**
 * The value of an `x5chain` COSE header (RFC 9360): a single certificate as a byte string, and a
 * chain of more than one certificate as an array, as in the examples of 18013-5 Annex D.
 */
export const x5chainHeaderValue = (certificateChain: Array<Uint8Array>): Uint8Array | Array<Uint8Array> =>
  certificateChain.length === 1 ? certificateChain[0] : certificateChain
