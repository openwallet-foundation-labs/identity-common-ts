import { CborStructure, zUint8Array } from '@owf/cose'
import z from 'zod'

const zOid4vpDcApiHandoverInfoEncoded = z.tuple([z.string(), z.string(), zUint8Array.nullable()])
const zOid4vpDcApiHandoverInfoDecoded = z.object({
  origin: z.string(),
  nonce: z.string(),
  jwkThumbprint: zUint8Array.nullable(),
})

export type Oid4vpDcApiHandoverInfoEncodedStructure = z.infer<typeof zOid4vpDcApiHandoverInfoEncoded>
export type Oid4vpDcApiHandoverInfoDecodedStructure = z.infer<typeof zOid4vpDcApiHandoverInfoDecoded>

export type Oid4vpDcApiHandoverInfoOptions = {
  origin: string
  nonce: string
  jwkThumbprint?: Uint8Array
}

export class Oid4vpDcApiHandoverInfo extends CborStructure<
  Oid4vpDcApiHandoverInfoEncodedStructure,
  Oid4vpDcApiHandoverInfoDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(zOid4vpDcApiHandoverInfoEncoded, zOid4vpDcApiHandoverInfoDecoded, {
      encode: ({ origin, nonce, jwkThumbprint }) =>
        [origin, nonce, jwkThumbprint] satisfies Oid4vpDcApiHandoverInfoEncodedStructure,
      decode: ([origin, nonce, jwkThumbprint]) => ({ origin, nonce, jwkThumbprint }),
    })
  }

  public get origin() {
    return this.structure.origin
  }

  public get nonce() {
    return this.structure.nonce
  }

  public get jwkThumbprint() {
    return this.structure.jwkThumbprint
  }

  public static create(options: Oid4vpDcApiHandoverInfoOptions) {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure({
      origin: options.origin,
      nonce: options.nonce,
      jwkThumbprint: options.jwkThumbprint ?? null,
    })
  }
}
