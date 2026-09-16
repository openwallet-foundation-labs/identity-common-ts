import { CborStructure, type DecodedStructureType, type EncodedStructureType } from '@owf/cose'

export abstract class Handover<EncodedStructure = unknown, DecodedStructure = EncodedStructure> extends CborStructure<
  EncodedStructure,
  DecodedStructure
> {
  // biome-ignore lint/suspicious/noExplicitAny: no explanation
  public static tryDecodeHandover<T extends Handover<any, any>>(
    this: {
      // biome-ignore lint/suspicious/noExplicitAny: no explanation
      new (structure: any): T
      fromEncodedStructure: (encodedStructure: EncodedStructureType<T>) => { decodedStructure: DecodedStructureType<T> }
    },
    structure: unknown
  ): T | null {
    try {
      // May feel weird, but using new this makes TypeScript understand we may return a subclass
      // biome-ignore lint/complexity/noThisInStatic: this.fromEncodedStructure is intentional for subclass support
      return new this(this.fromEncodedStructure(structure as EncodedStructureType<T>).decodedStructure)
    } catch {
      // We just return null if the parsing fails
      return null
    }
  }

  public get requiresReaderKey() {
    return false
  }

  public get requiresDeviceEngagement() {
    return false
  }
}
