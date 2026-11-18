import z from 'zod'
import { Handover } from './handover'

const zQrHandover = z.null()
export type QrHandoverStructure = z.infer<typeof zQrHandover>

export class QrHandover extends Handover<QrHandoverStructure> {
  public static override get encodingSchema() {
    return zQrHandover
  }

  public override get requiresReaderKey() {
    return true
  }

  public override get requiresDeviceEngagement() {
    return true
  }

  public static create() {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(null)
  }
}
