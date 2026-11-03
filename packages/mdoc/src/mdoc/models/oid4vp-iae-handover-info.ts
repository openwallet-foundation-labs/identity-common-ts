import { CborStructure, zUint8Array } from '@owf/cose'
import z from 'zod'

const zOid4vpIaeHandoverInfoEncoded = z.tuple([z.string(), z.string(), zUint8Array.nullable()])
const zOid4vpIaeHandoverInfoDecoded = z.object({
  interactiveAuthorizationEndpoint: z.string(),
  nonce: z.string(),
  jwkThumbprint: zUint8Array.nullable(),
})

export type Oid4vpIaeHandoverInfoEncodedStructure = z.infer<typeof zOid4vpIaeHandoverInfoEncoded>
export type Oid4vpIaeHandoverInfoDecodedStructure = z.infer<typeof zOid4vpIaeHandoverInfoDecoded>

export type Oid4vpIaeHandoverInfoOptions = {
  interactiveAuthorizationEndpoint: string
  nonce: string
  jwkThumbprint?: Uint8Array
}

export class Oid4vpIaeHandoverInfo extends CborStructure<
  Oid4vpIaeHandoverInfoEncodedStructure,
  Oid4vpIaeHandoverInfoDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(zOid4vpIaeHandoverInfoEncoded, zOid4vpIaeHandoverInfoDecoded, {
      encode: ({ interactiveAuthorizationEndpoint, nonce, jwkThumbprint }) =>
        [interactiveAuthorizationEndpoint, nonce, jwkThumbprint] satisfies Oid4vpIaeHandoverInfoEncodedStructure,
      decode: ([interactiveAuthorizationEndpoint, nonce, jwkThumbprint]) => ({
        interactiveAuthorizationEndpoint,
        nonce,
        jwkThumbprint,
      }),
    })
  }

  public get interactiveAuthorizationEndpoint() {
    return this.structure.interactiveAuthorizationEndpoint
  }

  public get nonce() {
    return this.structure.nonce
  }

  public get jwkThumbprint() {
    return this.structure.jwkThumbprint
  }

  public static create(options: Oid4vpIaeHandoverInfoOptions) {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure({
      interactiveAuthorizationEndpoint: options.interactiveAuthorizationEndpoint,
      nonce: options.nonce,
      jwkThumbprint: options.jwkThumbprint ?? null,
    })
  }
}
