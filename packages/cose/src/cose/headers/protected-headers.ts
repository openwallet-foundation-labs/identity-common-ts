import z from 'zod'
import { CborStructure } from '../../cbor/cbor-structure.js'
import { cborDecode, cborEncode } from '../../cbor/parser.js'
import { type AnyTypedMap, TypedMap } from '../../utils/typed-map.js'
import { zUint8Array } from '../../utils/zod.js'
import { type CoseHeaders, coseHeaderClaimsSchema } from './header-claims.js'

// Wire form: the header map is wrapped in a bstr (RFC 9052). `protectedHeadersDecodedStructure` is
// the plain map carried inside that bstr, kept for backwards compatibility.
export const protectedHeadersEncodedStructure = zUint8Array
export const protectedHeadersDecodedStructure = z.map(z.number(), z.unknown())

export type ProtectedHeadersEncodedStructure = z.infer<typeof protectedHeadersEncodedStructure>
export type ProtectedHeadersDecodedStructure = z.infer<typeof coseHeaderClaimsSchema>

/**
 * Wraps a header claims schema in the bstr the protected headers are carried in (RFC 9052), giving
 * the encoding schema for a {@link ProtectedHeaders} class.
 *
 * A profile subclasses `ProtectedHeaders` and overrides `encodingSchema` with this, passing a claims
 * schema built by `extendCoseHeaderClaims`. The headers are then validated against that schema
 * wherever the structure is built, the same way every other `CborStructure` validates itself.
 */
export function protectedHeadersSchema<ClaimsSchema extends z.ZodType>(
  claimsSchema: z.ZodCodec<z.ZodType, ClaimsSchema>
) {
  return z.codec(protectedHeadersEncodedStructure, claimsSchema.out, {
    // TODO: Senders SHOULD encode a zero-length map as a zero-length string rather than as a zero-length map
    encode: (decoded) => cborEncode((decoded as AnyTypedMap).toMap()) as Uint8Array<ArrayBuffer>,
    decode: (encoded) =>
      TypedMap.fromMap(cborDecode(encoded) as Map<number, unknown>) as unknown as z.input<ClaimsSchema>,
  })
}

export type ProtectedHeaderOptions = {
  protectedHeaders?: Map<number, unknown>
}

/**
 * The protected header map of a COSE structure.
 *
 * A profile that adds or narrows header labels subclasses this and overrides `encodingSchema` with
 * `protectedHeadersSchema(...)`, passing the type of the resulting map as `Headers`:
 *
 * ```ts
 * const claims = extendCoseHeaderClaims([[RegisteredCwtHeaderClaimKey.Typ, z.literal('application/example+cwt')]] as const)
 *
 * class ExampleProtectedHeaders extends ProtectedHeaders<CoseHeadersFor<typeof claims>> {
 *   public static override get encodingSchema() {
 *     return protectedHeadersSchema(claims)
 *   }
 * }
 * ```
 *
 * @template Headers - The typed view over the header map. Defaults to the registered COSE header
 *   claims.
 */
export class ProtectedHeaders<Headers extends AnyTypedMap = CoseHeaders> extends CborStructure<
  ProtectedHeadersEncodedStructure,
  Headers
> {
  public static override get encodingSchema(): z.ZodType {
    return protectedHeadersSchema(coseHeaderClaimsSchema)
  }

  public get headers(): Headers {
    return this.structure
  }

  public static create(options: ProtectedHeaderOptions) {
    return ProtectedHeaders.fromDecodedStructure(TypedMap.fromMap(options.protectedHeaders ?? new Map()))
  }
}
