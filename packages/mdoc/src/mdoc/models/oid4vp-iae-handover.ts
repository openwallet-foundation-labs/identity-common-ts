import { zUint8Array } from '@owf/cose'
import z from 'zod'
import type { MdocContext } from '../../context'
import { Handover } from './handover'
import type { Oid4vpIaeHandoverInfo } from './oid4vp-iae-handover-info'

const zOid4vpIaeHandoverEncoded = z.tuple([z.literal('OpenID4VCIIAEHandover'), zUint8Array])
const zOid4vpIaeHandoverDecoded = zUint8Array

export type Oid4vpIaeHandoverEncodedStructure = z.infer<typeof zOid4vpIaeHandoverEncoded>
export type Oid4vpIaeHandoverDecodedStructure = z.infer<typeof zOid4vpIaeHandoverDecoded>

export type Oid4vpIaeHandoverOptions = {
  oid4vpIaeHandoverInfo: Oid4vpIaeHandoverInfo
}

export class Oid4vpIaeHandover extends Handover<Oid4vpIaeHandoverEncodedStructure, Oid4vpIaeHandoverDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(zOid4vpIaeHandoverEncoded, zOid4vpIaeHandoverDecoded, {
      encode: (handoverInfoHash) =>
        ['OpenID4VCIIAEHandover', handoverInfoHash] satisfies Oid4vpIaeHandoverEncodedStructure,
      decode: ([, handoverInfoHash]) => handoverInfoHash,
    })
  }

  public static createFromHash(oid4vpIaeHandoverInfoHash: Uint8Array) {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(oid4vpIaeHandoverInfoHash)
  }

  public static async create(options: Oid4vpIaeHandoverOptions, ctx: Pick<MdocContext, 'crypto'>) {
    const oid4vpIaeHandoverInfoHash = await ctx.crypto.digest({
      digestAlgorithm: 'SHA-256',
      bytes: options.oid4vpIaeHandoverInfo.encode(),
    })

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(oid4vpIaeHandoverInfoHash)
  }
}
