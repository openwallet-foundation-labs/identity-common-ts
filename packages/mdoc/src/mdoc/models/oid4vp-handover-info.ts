import { CborStructure, zUint8Array } from '@owf/cose'
import z from 'zod'

const zOid4vpHandoverInfoEncoded = z.tuple([z.string(), z.string(), zUint8Array.nullable(), z.string()])
const zOid4vpHandoverInfoDecoded = z.object({
  clientId: z.string(),
  nonce: z.string(),
  jwkThumbprint: zUint8Array.nullable(),
  responseUri: z.string(),
})

export type Oid4vpHandoverInfoEncodedStructure = z.infer<typeof zOid4vpHandoverInfoEncoded>
export type Oid4vpHandoverInfoDecodedStructure = z.infer<typeof zOid4vpHandoverInfoDecoded>

export type Oid4vpHandoverInfoOptions = {
  clientId: string
  nonce: string
  jwkThumbprint?: Uint8Array
  responseUri: string
}

export class Oid4vpHandoverInfo extends CborStructure<
  Oid4vpHandoverInfoEncodedStructure,
  Oid4vpHandoverInfoDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(zOid4vpHandoverInfoEncoded, zOid4vpHandoverInfoDecoded, {
      encode: ({ clientId, nonce, jwkThumbprint, responseUri }) =>
        [clientId, nonce, jwkThumbprint, responseUri] satisfies Oid4vpHandoverInfoEncodedStructure,
      decode: ([clientId, nonce, jwkThumbprint, responseUri]) => ({ clientId, nonce, jwkThumbprint, responseUri }),
    })
  }

  public get clientId() {
    return this.structure.clientId
  }

  public get nonce() {
    return this.structure.nonce
  }

  public get jwkThumbprint() {
    return this.structure.jwkThumbprint
  }

  public get responseUri() {
    return this.structure.responseUri
  }

  public static create(options: Oid4vpHandoverInfoOptions) {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure({
      clientId: options.clientId,
      nonce: options.nonce,
      jwkThumbprint: options.jwkThumbprint ?? null,
      responseUri: options.responseUri,
    })
  }
}
