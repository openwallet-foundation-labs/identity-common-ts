import { CborStructure, TypedMap, typedMap, zUint8Array } from '@owf/cose'
import { z } from 'zod'
import { EReaderKey } from './e-reader-key'

const zSessionEstablishment = typedMap([
  ['eReaderKey', z.instanceof(EReaderKey)],
  ['data', zUint8Array],
] as const)

export type SessionEstablishmentDecodedStructure = z.output<typeof zSessionEstablishment>
export type SessionEstablishmentEncodedStructure = z.input<typeof zSessionEstablishment>

export type SessionEstablishmentOptions = {
  eReaderKey: EReaderKey
  data: Uint8Array
}

export class SessionEstablishment extends CborStructure<
  SessionEstablishmentEncodedStructure,
  SessionEstablishmentDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(zSessionEstablishment.in, zSessionEstablishment.out, {
      decode: (input) => {
        const map: SessionEstablishmentDecodedStructure = TypedMap.fromMap(input)

        const eReaderKeyDataItem = input.get('eReaderKey')
        map.set('eReaderKey', EReaderKey.fromDataItem(eReaderKeyDataItem))

        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        map.set('eReaderKey', output.get('eReaderKey').asDataItem)

        return map
      },
    })
  }

  public get eReaderKey() {
    return this.structure.get('eReaderKey')
  }

  public get data() {
    return this.structure.get('data')
  }

  public static create(options: SessionEstablishmentOptions): SessionEstablishment {
    const map: SessionEstablishmentDecodedStructure = new TypedMap([
      ['eReaderKey', options.eReaderKey],
      ['data', options.data],
    ])

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(map)
  }
}
