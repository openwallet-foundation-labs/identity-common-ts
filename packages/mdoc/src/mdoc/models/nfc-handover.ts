import { zUint8Array } from '@owf/cose'
import z from 'zod'
import { Handover } from './handover'

const zNfcHandoverEncoded = z.tuple([zUint8Array, zUint8Array.nullable()])
const zNfcHandoverDecoded = z.object({
  selectMessage: zUint8Array,
  requestMessage: zUint8Array.nullable(),
})

export type NfcHandoverEncodedStructure = z.infer<typeof zNfcHandoverEncoded>
export type NfcHandoverDecodedStructure = z.infer<typeof zNfcHandoverDecoded>

export type NfcHandoverOptions = {
  selectMessage: Uint8Array
  requestMessage?: Uint8Array
}

export class NfcHandover extends Handover<NfcHandoverEncodedStructure, NfcHandoverDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(zNfcHandoverEncoded, zNfcHandoverDecoded, {
      encode: ({ selectMessage, requestMessage }) =>
        [selectMessage, requestMessage] satisfies NfcHandoverEncodedStructure,
      decode: ([selectMessage, requestMessage]) => ({ selectMessage, requestMessage }),
    })
  }

  public get selectMessage() {
    return this.structure.selectMessage
  }

  public get requestMessage() {
    return this.structure.requestMessage
  }

  public static create(options: NfcHandoverOptions) {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure({
      requestMessage: options.requestMessage ?? null,
      selectMessage: options.selectMessage,
    })
  }

  public override get requiresReaderKey() {
    return true
  }

  public override get requiresDeviceEngagement() {
    return true
  }
}
