import { compareBytes } from '@owf/identity-common'
import type { AnyTypedMap } from '../../utils/typed-map.js'
import { CoseX5ChainNotBoundError } from '../error.js'
import { type DigestAlgorithm, RegisteredCwtHeaderClaimKey } from './defaults.js'
import type { ProtectedHeaders } from './protected-headers.js'
import type { UnprotectedHeaders } from './unprotected-headers.js'

/** SHA-256 in a COSE_CertHash (RFC 9360), as registered in RFC 9054. */
const COSE_SHA_256 = -16

export type X5ChainContext = {
  digest: (input: { digestAlgorithm: DigestAlgorithm; bytes: Uint8Array }) => Promise<Uint8Array> | Uint8Array
}

/**
 * The `x5chain` of a COSE structure, provided its end-entity certificate is integrity protected, as
 * RFC 9360 requires: read from the protected header, or else from the unprotected header when a
 * protected `x5t` matches its leaf. The unprotected header is not covered by the signature, so
 * without that binding the certificate could be replaced by another one for the same key.
 *
 * Only a SHA-256 `x5t` is supported.
 *
 * @returns the chain, leaf first, or `undefined` when neither header has an `x5chain`.
 * @throws CoseX5ChainNotBoundError if the `x5chain` is in the unprotected header but no protected `x5t` matches its leaf.
 */
export async function getIntegrityProtectedX5Chain(
  {
    protectedHeaders,
    unprotectedHeaders,
  }: { protectedHeaders: ProtectedHeaders<AnyTypedMap>; unprotectedHeaders: UnprotectedHeaders<AnyTypedMap> },
  ctx: X5ChainContext
): Promise<Array<Uint8Array> | undefined> {
  const protectedX5Chain = normalizeX5Chain(protectedHeaders.headers.get(RegisteredCwtHeaderClaimKey.X5Chain))
  if (protectedX5Chain) return protectedX5Chain

  const x5chain = normalizeX5Chain(unprotectedHeaders.headers.get(RegisteredCwtHeaderClaimKey.X5Chain))
  if (!x5chain) return undefined

  const x5t = protectedHeaders.headers.get(RegisteredCwtHeaderClaimKey.X5T)
  if (!Array.isArray(x5t) || x5t.length !== 2 || !(x5t[1] instanceof Uint8Array)) {
    throw new CoseX5ChainNotBoundError(
      'The x5chain is in the unprotected header, but the protected header has no x5t that binds it'
    )
  }

  const [hashAlgorithm, expectedHash] = x5t as [unknown, Uint8Array]
  if (hashAlgorithm !== COSE_SHA_256) {
    throw new CoseX5ChainNotBoundError(
      `The x5t of the protected header uses hash algorithm '${String(hashAlgorithm)}', only SHA-256 (-16) is supported`
    )
  }

  const leafHash = await ctx.digest({ digestAlgorithm: 'SHA-256', bytes: x5chain[0] })
  if (!compareBytes(leafHash, expectedHash)) {
    throw new CoseX5ChainNotBoundError(
      'The x5t of the protected header does not match the leaf of the x5chain in the unprotected header'
    )
  }

  return x5chain
}

/** COSE_X509 carries either a single certificate or a chain of them (RFC 9360). */
function normalizeX5Chain(x5chain: unknown): Array<Uint8Array> | undefined {
  const chain = x5chain instanceof Uint8Array ? [x5chain] : x5chain
  if (!Array.isArray(chain) || chain.length === 0 || !chain.every((c) => c instanceof Uint8Array)) return undefined
  return chain
}
