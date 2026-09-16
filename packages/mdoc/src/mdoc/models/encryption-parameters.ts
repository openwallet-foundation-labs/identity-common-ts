import { CborStructure, CoseKey, type CoseKeyEncodedStructure, TypedMap, typedMap, zUint8Array } from '@owf/cose'
import { z } from 'zod'

const encryptionParametersSchema = typedMap([
  ['nonce', zUint8Array],
  ['recipientPublicKey', z.instanceof(CoseKey)],
] as const)

export type EncryptionParametersDecodedStructure = z.output<typeof encryptionParametersSchema>
export type EncryptionParametersEncodedStructure = z.input<typeof encryptionParametersSchema>

export type EncryptionParametersOptions = {
  nonce: Uint8Array
  recipientPublicKey: CoseKey
}

/**
 * EncryptionParameters as defined in ISO/IEC TS 18013-7:2025 C.2.
 *
 *   EncryptionParameters = { "nonce": bstr, "recipientPublicKey": COSE_Key }
 */
export class EncryptionParameters extends CborStructure<
  EncryptionParametersEncodedStructure,
  EncryptionParametersDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(encryptionParametersSchema.in, encryptionParametersSchema.out, {
      decode: (input) => {
        const map = TypedMap.fromMap(input) as EncryptionParametersDecodedStructure

        map.set(
          'recipientPublicKey',
          CoseKey.fromEncodedStructure(input.get('recipientPublicKey') as CoseKeyEncodedStructure)
        )

        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        map.set('recipientPublicKey', output.get('recipientPublicKey').encodedStructure)

        return map
      },
    })
  }

  public get nonce() {
    return this.structure.get('nonce')
  }

  public get recipientPublicKey() {
    return this.structure.get('recipientPublicKey')
  }

  public static create(options: EncryptionParametersOptions): EncryptionParameters {
    const map: EncryptionParametersDecodedStructure = new TypedMap([
      ['nonce', options.nonce],
      ['recipientPublicKey', options.recipientPublicKey],
    ])

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(map)
  }
}
