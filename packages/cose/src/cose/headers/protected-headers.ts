import z from 'zod'
import {
  type AnyCborStructure,
  CborStructure,
  type CborStructureStaticThis,
  type EncodedStructureType,
} from '../../cbor/cbor-structure.js'
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
 * Headers decoded from a token keep the bstr they came from, so that verification uses the bytes the
 * issuer signed rather than our re-encoding of them. See {@link originalEncodedStructure}.
 *
 * @template Headers - The typed view over the header map. Defaults to the registered COSE header
 *   claims.
 */
export class ProtectedHeaders<Headers extends AnyTypedMap = CoseHeaders> extends CborStructure<
  ProtectedHeadersEncodedStructure,
  Headers
> {
  /**
   * The bstr this was decoded from, kept so that it is what goes back into the `Sig_structure` /
   * `MAC_structure` (RFC 9052 puts the protected headers in as an opaque bstr, so what was signed
   * is the exact bytes the issuer sent). Re-encoding the map instead is not byte-preserving for
   * input that is valid CBOR but not the form we would write — a non-shortest-form integer, an
   * indefinite-length map, a float, a bignum, a tag 0 date — and the signature over such a token
   * would fail to verify for no visible reason.
   *
   * Dropped as soon as the header map is changed, since the bytes no longer describe it.
   *
   * @see https://datatracker.ietf.org/doc/rfc9052/#section-4.4
   */
  private originalEncodedStructure?: ProtectedHeadersEncodedStructure

  public static override get encodingSchema(): z.ZodType {
    return protectedHeadersSchema(coseHeaderClaimsSchema)
  }

  public get headers(): Headers {
    return this.structure
  }

  /**
   * The header map as it goes on the wire: the bstr this was decoded from when it came from a
   * token and has not been changed since, and the encoded map otherwise.
   */
  public override get encodedStructure(): ProtectedHeadersEncodedStructure {
    return this.originalEncodedStructure ?? super.encodedStructure
  }

  /**
   * Drops the retained {@link originalEncodedStructure}, so that the headers are re-encoded the next
   * time they are used. Changing the header map does this on its own; call it after changing a
   * header *value* in place — `headers.get(x5chain)[0] = ...` — which the map cannot see.
   */
  public markModified() {
    this.originalEncodedStructure = undefined
  }

  public static override fromEncodedStructure<T extends AnyCborStructure>(
    this: CborStructureStaticThis<T>,
    encodedStructure: EncodedStructureType<T>
  ): T {
    // biome-ignore lint/complexity/noThisInStatic: `super` keeps `this` bound to the subclass it was called on, which is what constructs a profile's header class rather than this one
    const headers = super.fromEncodedStructure(encodedStructure) as T & ProtectedHeaders<AnyTypedMap>

    // NOTE: copied, because the decoder hands back a view onto the buffer the whole token was
    // decoded from.
    headers.originalEncodedStructure = new Uint8Array(encodedStructure as Uint8Array)
    headers.headers.onChange = () => headers.markModified()

    return headers
  }

  public static create(options: ProtectedHeaderOptions) {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(TypedMap.fromMap(options.protectedHeaders ?? new Map()))
  }
}
