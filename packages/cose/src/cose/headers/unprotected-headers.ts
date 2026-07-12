import z from 'zod'
import { CborStructure } from '../../cbor/cbor-structure.js'
import { TypedMap } from '../../utils/typed-map.js'
import { type CoseHeaders, coseHeaderClaimsSchema } from './header-claims.js'

// Wire form: a plain map of integer label -> value (used by the COSE_Sign1 encoded schema).
export const unprotectedHeadersStructure = z.map(z.number(), z.unknown())

export type UnprotectedHeadersEncodedStructure = z.infer<typeof unprotectedHeadersStructure>
export type UnprotectedHeadersDecodedStructure = z.infer<typeof coseHeaderClaimsSchema>

// Backwards-compatible alias for the wire structure.
export type UnprotectedHeadersStructure = UnprotectedHeadersEncodedStructure

export type UnprotectedHeaderOptions = {
  unprotectedHeaders?: UnprotectedHeadersEncodedStructure
}

export class UnprotectedHeaders extends CborStructure<
  UnprotectedHeadersEncodedStructure,
  UnprotectedHeadersDecodedStructure
> {
  public static override get encodingSchema() {
    return coseHeaderClaimsSchema
  }

  public get headers(): CoseHeaders {
    return this.structure as unknown as CoseHeaders
  }

  public static create(options: UnprotectedHeaderOptions) {
    return UnprotectedHeaders.fromDecodedStructure(TypedMap.fromMap(options.unprotectedHeaders ?? new Map()))
  }
}
