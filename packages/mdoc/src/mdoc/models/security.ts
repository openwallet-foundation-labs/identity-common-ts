import { CborStructure, DataItem } from '@owf/cose'
import { z } from 'zod'
import { EDeviceKey } from './e-device-key'

const zSecurityEncoded = z.tuple([z.number(), z.instanceof(DataItem)])

const zSecurityDecoded = z.object({
  cipherSuiteIdentifier: z.number(),
  eDeviceKey: z.instanceof(EDeviceKey),
})

export type SecurityEncodedStructure = z.infer<typeof zSecurityEncoded>
export type SecurityDecodedStructure = z.infer<typeof zSecurityDecoded>

export type SecurityOptions = {
  cipherSuiteIdentifier: number
  eDeviceKey: EDeviceKey
}

export class Security extends CborStructure<SecurityEncodedStructure, SecurityDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(zSecurityEncoded, zSecurityDecoded, {
      decode: (input) => ({
        cipherSuiteIdentifier: input[0],
        // biome-ignore lint/suspicious/noExplicitAny: CoseKey encoded structure
        eDeviceKey: EDeviceKey.fromEncodedStructure((input[1] as DataItem).data as any),
      }),
      encode: (output): SecurityEncodedStructure => [
        output.cipherSuiteIdentifier,
        DataItem.fromData(output.eDeviceKey.encodedStructure),
      ],
    })
  }

  public get cipherSuiteIdentifier() {
    return this.structure.cipherSuiteIdentifier
  }

  public get eDeviceKey() {
    return this.structure.eDeviceKey
  }

  public static create(options: SecurityOptions): Security {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure({
      cipherSuiteIdentifier: options.cipherSuiteIdentifier,
      eDeviceKey: options.eDeviceKey,
    })
  }
}
