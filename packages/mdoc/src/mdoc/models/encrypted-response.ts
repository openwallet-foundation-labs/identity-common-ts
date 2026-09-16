import { CborStructure } from '@owf/cose'
import { base64url } from '@owf/identity-common'
import { z } from 'zod'
import { EncryptedResponseData, type EncryptedResponseDataEncodedStructure } from './encrypted-response-data'

const encryptedResponseEncodedSchema = z.tuple([z.literal('dcapi'), z.map(z.unknown(), z.unknown())])
const encryptedResponseDecodedSchema = z.instanceof(EncryptedResponseData)

export type EncryptedResponseEncodedStructure = z.infer<typeof encryptedResponseEncodedSchema>
export type EncryptedResponseDecodedStructure = z.infer<typeof encryptedResponseDecodedSchema>

export type EncryptedResponseOptions = {
  encryptedResponseData: EncryptedResponseData
}

/**
 * EncryptedResponse as defined in ISO/IEC TS 18013-7:2025 C.3.
 *
 *   EncryptedResponse = [ "dcapi", EncryptedResponseData ]
 */
export class EncryptedResponse extends CborStructure<
  EncryptedResponseEncodedStructure,
  EncryptedResponseDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(encryptedResponseEncodedSchema, encryptedResponseDecodedSchema, {
      decode: ([, encryptedResponseData]) =>
        EncryptedResponseData.fromEncodedStructure(encryptedResponseData as EncryptedResponseDataEncodedStructure),
      encode: (encryptedResponseData) =>
        ['dcapi', encryptedResponseData.encodedStructure] satisfies EncryptedResponseEncodedStructure,
    })
  }

  public get encryptedResponseData() {
    return this.structure
  }

  public get enc() {
    return this.structure.enc
  }

  public get ciphertext() {
    return this.structure.ciphertext
  }

  public static create(options: EncryptedResponseOptions): EncryptedResponse {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(options.encryptedResponseData)
  }

  public static fromBase64Url(encryptedResponse: string): EncryptedResponse {
    // biome-ignore lint/complexity/noThisInStatic: this.decode is intentional for subclass support
    return this.decode(base64url.decode(encryptedResponse))
  }

  public toBase64Url(): string {
    return base64url.encode(this.encode())
  }
}
