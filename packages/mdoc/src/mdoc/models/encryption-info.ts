import { CborStructure } from '@owf/cose'
import { base64url } from '@owf/identity-common'
import { z } from 'zod'
import { EncryptionParameters, type EncryptionParametersEncodedStructure } from './encryption-parameters'

const encryptionInfoEncodedSchema = z.tuple([z.literal('dcapi'), z.map(z.unknown(), z.unknown())])
const encryptionInfoDecodedSchema = z.instanceof(EncryptionParameters)

export type EncryptionInfoEncodedStructure = z.infer<typeof encryptionInfoEncodedSchema>
export type EncryptionInfoDecodedStructure = z.infer<typeof encryptionInfoDecodedSchema>

export type EncryptionInfoOptions = {
  encryptionParameters: EncryptionParameters
}

/**
 * EncryptionInfo as defined in ISO/IEC TS 18013-7:2025 C.2.
 *
 *   EncryptionInfo = [ "dcapi", EncryptionParameters ]
 */
export class EncryptionInfo extends CborStructure<EncryptionInfoEncodedStructure, EncryptionInfoDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(encryptionInfoEncodedSchema, encryptionInfoDecodedSchema, {
      decode: ([, encryptionParameters]) =>
        EncryptionParameters.fromEncodedStructure(encryptionParameters as EncryptionParametersEncodedStructure),
      encode: (encryptionParameters) =>
        ['dcapi', encryptionParameters.encodedStructure] satisfies EncryptionInfoEncodedStructure,
    })
  }

  public get encryptionParameters() {
    return this.structure
  }

  public get nonce() {
    return this.structure.nonce
  }

  public get recipientPublicKey() {
    return this.structure.recipientPublicKey
  }

  public static create(options: EncryptionInfoOptions): EncryptionInfo {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(options.encryptionParameters)
  }

  public static fromBase64Url(encryptionInfo: string): EncryptionInfo {
    // biome-ignore lint/complexity/noThisInStatic: this.decode is intentional for subclass support
    return this.decode(base64url.decode(encryptionInfo))
  }

  public toBase64Url(): string {
    return base64url.encode(this.encode())
  }
}
