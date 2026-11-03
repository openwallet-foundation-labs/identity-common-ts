import { CborStructure } from '@owf/cose'
import z from 'zod'

const zProtocolInfo = z.unknown()
export type ProtocolInfoStructure = z.infer<typeof zProtocolInfo>

export class ProtocolInfo extends CborStructure<ProtocolInfoStructure> {
  public static override get encodingSchema() {
    return zProtocolInfo
  }
}
