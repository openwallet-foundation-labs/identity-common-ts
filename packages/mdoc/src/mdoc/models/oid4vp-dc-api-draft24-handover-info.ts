import { CborStructure } from '@owf/cose'
import z from 'zod'

const zOid4vpDcApiDraft24HandoverInfo = z.tuple([z.string(), z.string(), z.string()])
const zOid4vpDcApiDraft24HandoverInfoDecoded = z.object({
  origin: z.string(),
  clientId: z.string(),
  nonce: z.string(),
})

export type Oid4vpDcApiDraft24HandoverInfoEncodedStructure = z.infer<typeof zOid4vpDcApiDraft24HandoverInfo>
export type Oid4vpDcApiDraft24HandoverInfoDecodedStructure = z.infer<typeof zOid4vpDcApiDraft24HandoverInfoDecoded>

export type Oid4vpDcApiDraft24HandoverInfoOptions = {
  origin: string
  clientId: string
  nonce: string
}

export class Oid4vpDcApiDraft24HandoverInfo extends CborStructure<
  Oid4vpDcApiDraft24HandoverInfoEncodedStructure,
  Oid4vpDcApiDraft24HandoverInfoDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(zOid4vpDcApiDraft24HandoverInfo, zOid4vpDcApiDraft24HandoverInfoDecoded, {
      encode: ({ origin, clientId, nonce }) =>
        [origin, clientId, nonce] satisfies Oid4vpDcApiDraft24HandoverInfoEncodedStructure,
      decode: ([origin, clientId, nonce]) => ({ origin, clientId, nonce }),
    })
  }

  public get origin() {
    return this.structure.origin
  }

  public get clientId() {
    return this.structure.clientId
  }

  public get nonce() {
    return this.structure.nonce
  }

  public static create(options: Oid4vpDcApiDraft24HandoverInfoOptions) {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure({
      origin: options.origin,
      clientId: options.clientId,
      nonce: options.nonce,
    })
  }
}
