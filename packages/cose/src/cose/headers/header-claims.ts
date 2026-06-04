import z from 'zod'
import { type TypedMap, typedMap } from '../../utils/typed-map.js'
import { zUint8Array } from '../../utils/zod.js'
import { RegisteredCwtHeaderClaimKey } from './defaults.js'

/**
 * Schema for the known COSE header claims (RFC 9052 Section 3.1 / the IANA COSE Header Parameters
 * registry). Shared by the protected and unprotected header structures.
 *
 * `kid` (4) is typed as a bstr (`Uint8Array`): a header carrying a `kid` whose value is not a bstr
 * (e.g. a malformed `{ 4: undefined }`) is rejected at decode for every Sign1-derived structure.
 *
 * The other registered labels are enumerated as known keys but left permissively typed (`unknown`)
 * so that valid-but-variably-shaped encodings are not rejected. Additional (unregistered or
 * private-use) labels are allowed through (`allowAdditionalKeys`).
 */
// Any defined (non-`undefined`) value. Apart from `kid`, the registered labels are enumerated as
// known keys but not constrained to a specific value type (their CBOR shapes vary and we do not want
// to reject valid encodings). Rejecting `undefined` both keeps a malformed `{ <label>: undefined }`
// out and lets `.exactOptional()` correctly mark the key as optional.
const zDefinedValue = z.unknown().refine((value) => value !== undefined)

export const coseHeaderClaimsSchema = typedMap(
  [
    [RegisteredCwtHeaderClaimKey.Algorithm, zDefinedValue.exactOptional()],
    [RegisteredCwtHeaderClaimKey.Critical, zDefinedValue.exactOptional()],
    [RegisteredCwtHeaderClaimKey.ContentType, zDefinedValue.exactOptional()],
    [RegisteredCwtHeaderClaimKey.KeyId, zUint8Array.exactOptional()],
    [RegisteredCwtHeaderClaimKey.Iv, zDefinedValue.exactOptional()],
    [RegisteredCwtHeaderClaimKey.PartialIv, zDefinedValue.exactOptional()],
    [RegisteredCwtHeaderClaimKey.X5Bag, zDefinedValue.exactOptional()],
    [RegisteredCwtHeaderClaimKey.X5Chain, zDefinedValue.exactOptional()],
    [RegisteredCwtHeaderClaimKey.X5T, zDefinedValue.exactOptional()],
    [RegisteredCwtHeaderClaimKey.X5U, zDefinedValue.exactOptional()],
  ] as const,
  { allowAdditionalKeys: true }
)

export type CoseHeaderClaims = z.infer<typeof coseHeaderClaimsSchema>

/**
 * Read/write view over a COSE header map. `kid` (4) is typed as a bstr, while any other integer label
 * remains accessible because COSE headers are open-ended (RFC 9052 / private-use range). The `kid`
 * type is enforced at decode by `coseHeaderClaimsSchema`; this view only governs typed access.
 */
export type CoseHeaders = TypedMap<
  { [RegisteredCwtHeaderClaimKey.KeyId]: Uint8Array } & Record<number, unknown>,
  RegisteredCwtHeaderClaimKey.KeyId
>
