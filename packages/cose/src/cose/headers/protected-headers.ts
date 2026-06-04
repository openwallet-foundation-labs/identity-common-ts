import z from 'zod'
import { CborStructure } from '../../cbor/cbor-structure.js'
import { cborDecode, cborEncode } from '../../cbor/parser.js'
import { TypedMap } from '../../utils/typed-map.js'
import { zUint8Array } from '../../utils/zod.js'
import { type CoseHeaders, coseHeaderClaimsSchema } from './header-claims.js'

// Wire form: the header map is wrapped in a bstr (RFC 9052). `protectedHeadersDecodedStructure` is
// the plain map carried inside that bstr, kept for backwards compatibility.
export const protectedHeadersEncodedStructure = zUint8Array
export const protectedHeadersDecodedStructure = z.map(z.number(), z.unknown())

export type ProtectedHeadersEncodedStructure = z.infer<typeof protectedHeadersEncodedStructure>
export type ProtectedHeadersDecodedStructure = z.infer<typeof coseHeaderClaimsSchema>

export type ProtectedHeaderOptions = {
  protectedHeaders?: Map<number, unknown>
}

export class ProtectedHeaders extends CborStructure<
  ProtectedHeadersEncodedStructure,
  ProtectedHeadersDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(protectedHeadersEncodedStructure, coseHeaderClaimsSchema.out, {
      // TODO: Senders SHOULD encode a zero-length map as a zero-length string rather than as a zero-length map
      encode: (decoded) => cborEncode(decoded.toMap()) as Uint8Array<ArrayBuffer>,
      decode: (encoded) => TypedMap.fromMap(cborDecode(encoded) as Map<number, unknown>),
    })
  }

  public get headers(): CoseHeaders {
    return this.structure as unknown as CoseHeaders
  }

  public static create(options: ProtectedHeaderOptions) {
    return ProtectedHeaders.fromDecodedStructure(TypedMap.fromMap(options.protectedHeaders ?? new Map()))
  }
}
