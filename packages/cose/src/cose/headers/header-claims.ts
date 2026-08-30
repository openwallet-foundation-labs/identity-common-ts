import z from 'zod'
import {
  type EntriesBase,
  type ExtendedEntries,
  extendTypedMapEntries,
  type TypedMap,
  typedMap,
} from '../../utils/typed-map.js'
import { zUint8Array } from '../../utils/zod.js'
import { RegisteredCwtHeaderClaimKey } from './defaults.js'

// A COSE label is an integer (registry) or a text string (private use).
const zCoseLabel = z.union([z.number(), z.string()])
// COSE_X509: a single certificate (bstr) or a chain (array of bstr). Used by x5bag/x5chain.
const zCertOrChain = z.union([zUint8Array, z.array(zUint8Array)])

/**
 * The known COSE header claims (RFC 9052 Section 3.1 / RFC 9360 / RFC 9596 / the IANA COSE Header
 * Parameters registry), as `typedMap` entries.
 *
 * Exported separately from {@link coseHeaderClaimsSchema} so a profile can build on them with
 * {@link extendCoseHeaderClaims}.
 */
export const coseHeaderClaimEntries = [
  [RegisteredCwtHeaderClaimKey.Algorithm, zCoseLabel.exactOptional()],
  [RegisteredCwtHeaderClaimKey.Critical, z.array(zCoseLabel).exactOptional()],
  [RegisteredCwtHeaderClaimKey.ContentType, zCoseLabel.exactOptional()],
  [RegisteredCwtHeaderClaimKey.KeyId, zUint8Array.exactOptional()],
  [RegisteredCwtHeaderClaimKey.Iv, zUint8Array.exactOptional()],
  [RegisteredCwtHeaderClaimKey.PartialIv, zUint8Array.exactOptional()],
  // RFC 9596: a media type as a text string, or a CoAP Content-Format integer.
  [RegisteredCwtHeaderClaimKey.Typ, zCoseLabel.exactOptional()],
  [RegisteredCwtHeaderClaimKey.X5Bag, zCertOrChain.exactOptional()],
  [RegisteredCwtHeaderClaimKey.X5Chain, zCertOrChain.exactOptional()],
  [RegisteredCwtHeaderClaimKey.X5T, z.array(z.unknown()).exactOptional()],
  [RegisteredCwtHeaderClaimKey.X5U, z.string().exactOptional()],
] as const

/**
 * Schema for the known COSE header claims. Shared by the protected and unprotected header
 * structures.
 *
 * Each registered label is typed to its CBOR shape; in particular `kid` (4) is a bstr (`Uint8Array`),
 * so a header carrying a `kid` whose value is not a bstr (e.g. a malformed `{ 4: undefined }`) is
 * rejected at decode for every Sign1-derived structure. Additional (unregistered or private-use)
 * labels are allowed through (`allowAdditionalKeys`).
 */
export const coseHeaderClaimsSchema = typedMap(coseHeaderClaimEntries, {
  allowAdditionalKeys: true,
  keyLabels: RegisteredCwtHeaderClaimKey,
})

export type CoseHeaderClaims = z.infer<typeof coseHeaderClaimsSchema>

export type ExtendedCoseHeaderClaimEntries<Entries extends EntriesBase> = ExtendedEntries<
  typeof coseHeaderClaimEntries,
  Entries
>

/**
 * Builds a header claims schema for a specific COSE/CWT profile: the registered COSE header claims
 * plus the given ones. An entry reusing a registered label replaces it, so a profile can also
 * narrow an existing claim (e.g. requiring `typ` to be a specific media type).
 *
 * @example
 * ```ts
 * const statusListHeaderClaimsSchema = extendCoseHeaderClaims([
 *   [RegisteredCwtHeaderClaimKey.Typ, z.literal('application/statuslist+cwt')],
 * ] as const)
 * ```
 */
export function extendCoseHeaderClaims<const Entries extends EntriesBase>(
  entries: Entries
): ReturnType<typeof typedMap<ExtendedCoseHeaderClaimEntries<Entries>>> {
  return typedMap(extendTypedMapEntries(coseHeaderClaimEntries, entries), { allowAdditionalKeys: true })
}

// Widen a typed-map type to also allow access to any other integer label.
type OpenIntegerKeys<T> =
  T extends TypedMap<infer Schema, infer Optional> ? TypedMap<Schema & Record<number, unknown>, Optional> : never

/**
 * Read/write view over a COSE header map: the typed claims above plus open access to any other
 * integer label, because COSE headers are open-ended (unregistered and private-use labels are valid).
 * The typed claims are still validated at decode by `coseHeaderClaimsSchema`; this view only governs
 * typed access.
 */
export type CoseHeaders = OpenIntegerKeys<CoseHeaderClaims>

/**
 * The {@link CoseHeaders} view for a profile-specific header claims schema, i.e. one built with
 * {@link extendCoseHeaderClaims}.
 */
export type CoseHeadersFor<Schema extends z.ZodType> = OpenIntegerKeys<z.infer<Schema>>
