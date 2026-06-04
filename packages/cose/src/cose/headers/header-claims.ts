import z from 'zod'
import { type TypedMap, typedMap } from '../../utils/typed-map.js'
import { zUint8Array } from '../../utils/zod.js'
import { RegisteredCwtHeaderClaimKey } from './defaults.js'

// A COSE label is an integer (registry) or a text string (private use).
const zCoseLabel = z.union([z.number(), z.string()])
// COSE_X509: a single certificate (bstr) or a chain (array of bstr). Used by x5bag/x5chain.
const zCertOrChain = z.union([zUint8Array, z.array(zUint8Array)])

/**
 * Schema for the known COSE header claims (RFC 9052 Section 3.1 / RFC 9360 / the IANA COSE Header
 * Parameters registry). Shared by the protected and unprotected header structures.
 *
 * Each registered label is typed to its CBOR shape; in particular `kid` (4) is a bstr (`Uint8Array`),
 * so a header carrying a `kid` whose value is not a bstr (e.g. a malformed `{ 4: undefined }`) is
 * rejected at decode for every Sign1-derived structure. Additional (unregistered or private-use)
 * labels are allowed through (`allowAdditionalKeys`).
 */
export const coseHeaderClaimsSchema = typedMap(
  [
    [RegisteredCwtHeaderClaimKey.Algorithm, zCoseLabel.exactOptional()],
    [RegisteredCwtHeaderClaimKey.Critical, z.array(zCoseLabel).exactOptional()],
    [RegisteredCwtHeaderClaimKey.ContentType, zCoseLabel.exactOptional()],
    [RegisteredCwtHeaderClaimKey.KeyId, zUint8Array.exactOptional()],
    [RegisteredCwtHeaderClaimKey.Iv, zUint8Array.exactOptional()],
    [RegisteredCwtHeaderClaimKey.PartialIv, zUint8Array.exactOptional()],
    [RegisteredCwtHeaderClaimKey.X5Bag, zCertOrChain.exactOptional()],
    [RegisteredCwtHeaderClaimKey.X5Chain, zCertOrChain.exactOptional()],
    [RegisteredCwtHeaderClaimKey.X5T, z.array(z.unknown()).exactOptional()],
    [RegisteredCwtHeaderClaimKey.X5U, z.string().exactOptional()],
  ] as const,
  { allowAdditionalKeys: true }
)

export type CoseHeaderClaims = z.infer<typeof coseHeaderClaimsSchema>

// Widen a typed-map type to also allow access to any other integer label.
type OpenIntegerKeys<T> =
  T extends TypedMap<infer Schema, infer Optional> ? TypedMap<Schema & Record<number, unknown>, Optional> : never

/**
 * Read/write view over a COSE header map: the typed claims above plus open access to any other
 * integer label, because COSE headers are open-ended (unregistered and private-use labels are valid,
 * e.g. a status list's `typ`). The typed claims are still validated at decode by
 * `coseHeaderClaimsSchema`; this view only governs typed access.
 */
export type CoseHeaders = OpenIntegerKeys<CoseHeaderClaims>
