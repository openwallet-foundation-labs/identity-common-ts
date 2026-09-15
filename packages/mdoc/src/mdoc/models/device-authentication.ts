import { CborStructure, DataItem } from '@owf/cose'
import { z } from 'zod'
import { DeviceNamespaces, type DeviceNamespacesEncodedStructure } from './device-namespaces'
import type { DocType } from './doctype'
import { SessionTranscript, sessionTranscriptEncodedSchema } from './session-transcript'

const deviceAuthenticationEncodedSchema = z.tuple([
  z.literal('DeviceAuthentication'),
  sessionTranscriptEncodedSchema,
  z.string(),
  z.instanceof<typeof DataItem<DeviceNamespacesEncodedStructure>>(DataItem),
])

const deviceAuthenticationDecodedSchema = z.object({
  sessionTranscript: z.instanceof(SessionTranscript),
  docType: z.string(),
  deviceNamespaces: z.instanceof(DeviceNamespaces),
})

export type DeviceAuthenticationDecodedStructure = z.infer<typeof deviceAuthenticationDecodedSchema>
export type DeviceAuthenticationEncodedStructure = z.infer<typeof deviceAuthenticationEncodedSchema>

export type DeviceAuthenticationOptions = {
  sessionTranscript: SessionTranscript | Uint8Array
  docType: DocType
  deviceNamespaces: DeviceNamespaces
}

export class DeviceAuthentication extends CborStructure<
  DeviceAuthenticationEncodedStructure,
  DeviceAuthenticationDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(deviceAuthenticationEncodedSchema, deviceAuthenticationDecodedSchema, {
      decode: ([, sessionTranscript, docType, deviceNamespacesDataItem]) => ({
        sessionTranscript: SessionTranscript.fromEncodedStructure(sessionTranscript),
        docType,
        deviceNamespaces: DeviceNamespaces.fromDataItem(deviceNamespacesDataItem),
      }),
      encode: ({ sessionTranscript, docType, deviceNamespaces }) =>
        [
          'DeviceAuthentication',
          sessionTranscript.encodedStructure,
          docType,
          // `DeviceNameSpacesBytes` are authenticated as the mdoc sent them (18013-5 8.1).
          deviceNamespaces.asDataItem,
        ] satisfies DeviceAuthenticationEncodedStructure,
    })
  }

  public get sessionTranscript() {
    return this.structure.sessionTranscript
  }

  public get docType() {
    return this.structure.docType
  }

  public get deviceNamespaces() {
    return this.structure.deviceNamespaces
  }

  public static create(options: DeviceAuthenticationOptions): DeviceAuthentication {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure({
      sessionTranscript: SessionTranscript.from(options.sessionTranscript),
      docType: options.docType,
      deviceNamespaces: options.deviceNamespaces,
    })
  }
}
