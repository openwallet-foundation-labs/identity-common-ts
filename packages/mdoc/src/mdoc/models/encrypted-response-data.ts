import { CborStructure, TypedMap, typedMap, zUint8Array } from '@owf/cose'
import type { z } from 'zod'

const encryptedResponseDataSchema = typedMap([
  ['enc', zUint8Array],
  ['cipherText', zUint8Array],
] as const)

export type EncryptedResponseDataDecodedStructure = z.output<typeof encryptedResponseDataSchema>
export type EncryptedResponseDataEncodedStructure = z.input<typeof encryptedResponseDataSchema>

export type EncryptedResponseDataOptions = {
  /**
   * Raw serialized HPKE encapsulated key. For DHKEM(P-256) this is the 65-byte
   * uncompressed SEC1 point, not a COSE_Key.
   */
  enc: Uint8Array
  ciphertext: Uint8Array
}

/**
 * EncryptedResponseData as defined in ISO/IEC TS 18013-7:2025 C.3.
 *
 *   EncryptedResponseData = { "enc": bstr, "cipherText": bstr }
 */
export class EncryptedResponseData extends CborStructure<
  EncryptedResponseDataEncodedStructure,
  EncryptedResponseDataDecodedStructure
> {
  public static override get encodingSchema() {
    return encryptedResponseDataSchema
  }

  public get enc() {
    return this.structure.get('enc')
  }

  public get ciphertext() {
    return this.structure.get('cipherText')
  }

  public static create(options: EncryptedResponseDataOptions): EncryptedResponseData {
    const map: EncryptedResponseDataDecodedStructure = new TypedMap([
      ['enc', options.enc],
      ['cipherText', options.ciphertext],
    ])

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(map)
  }
}
