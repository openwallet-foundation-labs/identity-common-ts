import z from 'zod'
import { CborStructure } from '../../cbor/cbor-structure.js'
import { type AnyTypedMap, TypedMap } from '../../utils/typed-map.js'
import { type CoseHeaders, zCoseHeaderClaims } from './header-claims.js'

// Wire form: a plain map of integer label -> value (used by the COSE_Sign1 encoded schema).
export const zUnprotectedHeaders = z.map(z.number(), z.unknown())

export type UnprotectedHeadersEncodedStructure = z.infer<typeof zUnprotectedHeaders>
export type UnprotectedHeadersDecodedStructure = z.infer<typeof zCoseHeaderClaims>

// Backwards-compatible alias for the wire structure.
export type UnprotectedHeadersStructure = UnprotectedHeadersEncodedStructure

export type UnprotectedHeaderOptions = {
  unprotectedHeaders?: UnprotectedHeadersEncodedStructure
}

/**
 * The unprotected header map of a COSE structure. Subclassed the same way as
 * {@link ProtectedHeaders}, except that the claims schema is the encoding schema directly, since
 * the unprotected headers are carried as a plain map rather than wrapped in a bstr.
 *
 * @template Headers - The typed view over the header map. See {@link ProtectedHeaders}.
 */
export class UnprotectedHeaders<Headers extends AnyTypedMap = CoseHeaders> extends CborStructure<
  UnprotectedHeadersEncodedStructure,
  Headers
> {
  public static override get encodingSchema(): z.ZodType {
    return zCoseHeaderClaims
  }

  public get headers(): Headers {
    return this.structure
  }

  public static create(options: UnprotectedHeaderOptions) {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(TypedMap.fromMap(options.unprotectedHeaders ?? new Map()))
  }
}
