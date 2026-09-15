import { CborStructure, TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import { DeviceAuth, type DeviceAuthEncodedStructure } from './device-auth'
import { DeviceNamespaces } from './device-namespaces'

const deviceSignedSchema = typedMap([
  ['nameSpaces', z.instanceof(DeviceNamespaces)],
  ['deviceAuth', z.instanceof(DeviceAuth)],
] as const)

export type DeviceSignedDecodedStructure = z.output<typeof deviceSignedSchema>
export type DeviceSignedEncodedStructure = z.input<typeof deviceSignedSchema>

export type DeviceSignedOptions = {
  deviceNamespaces: DeviceNamespaces
  deviceAuth: DeviceAuth
}

export class DeviceSigned extends CborStructure<DeviceSignedEncodedStructure, DeviceSignedDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(deviceSignedSchema.in, deviceSignedSchema.out, {
      decode: (input) => {
        const map: DeviceSignedDecodedStructure = TypedMap.fromMap(input)

        map.set('nameSpaces', DeviceNamespaces.fromDataItem(input.get('nameSpaces')))
        map.set('deviceAuth', DeviceAuth.fromEncodedStructure(input.get('deviceAuth') as DeviceAuthEncodedStructure))

        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        // `DeviceNameSpacesBytes` are embedded as received, as device authentication covers them.
        map.set('nameSpaces', output.get('nameSpaces').asDataItem)
        map.set('deviceAuth', output.get('deviceAuth').encodedStructure)

        return map
      },
    })
  }

  public get deviceNamespaces() {
    return this.structure.get('nameSpaces')
  }

  public get deviceAuth() {
    return this.structure.get('deviceAuth')
  }

  public static create(options: DeviceSignedOptions): DeviceSigned {
    const map: DeviceSignedDecodedStructure = new TypedMap([
      ['nameSpaces', options.deviceNamespaces],
      ['deviceAuth', options.deviceAuth],
    ])
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(map)
  }
}
