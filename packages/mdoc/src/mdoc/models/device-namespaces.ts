import { z } from 'zod'
import { OriginalBytesCborStructure } from '../original-bytes-cbor-structure'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DataElementValue } from './data-element-value'
import { DeviceSignedItems, type DeviceSignedItemsStructure, zDeviceSignedItems } from './device-signed-items'
import type { Namespace } from './namespace'

const zDeviceNamespacesEncoded = z.map(z.string(), zDeviceSignedItems)
const zDeviceNamespacesDecoded = z.map(z.string(), z.instanceof(DeviceSignedItems))

export type DeviceNamespacesDecodedStructure = z.infer<typeof zDeviceNamespacesDecoded>
export type DeviceNamespacesEncodedStructure = z.infer<typeof zDeviceNamespacesEncoded>

export type DeviceNamespacesOptions = {
  deviceNamespaces: Map<Namespace, DeviceSignedItems>
}

export class DeviceNamespaces extends OriginalBytesCborStructure<
  DeviceNamespacesEncodedStructure,
  DeviceNamespacesDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(zDeviceNamespacesEncoded, zDeviceNamespacesDecoded, {
      decode: (input) => {
        const deviceNamespaces = new Map<Namespace, DeviceSignedItems>()
        input.forEach((value, key) => {
          deviceNamespaces.set(key, DeviceSignedItems.fromEncodedStructure(value as DeviceSignedItemsStructure))
        })
        return deviceNamespaces
      },
      encode: (output) => {
        const map = new Map()
        output.forEach((value, key) => {
          map.set(key, value.encodedStructure)
        })
        return map
      },
    })
  }

  /**
   * The device namespaces. Call {@link markModified} after changing them in place, or use
   * {@link setDeviceNamespace} and {@link setDeviceSignedElement}.
   */
  public get deviceNamespaces() {
    return this.structure
  }

  public getDeviceNamespace(namespace: Namespace) {
    return this.structure.get(namespace)
  }

  public setDeviceNamespace(namespace: Namespace, deviceSignedItems: DeviceSignedItems) {
    this.structure.set(namespace, deviceSignedItems)
    this.markModified()
  }

  /**
   * Sets an element in a namespace, and adds the namespace if it is not there yet.
   */
  public setDeviceSignedElement(
    namespace: Namespace,
    elementIdentifier: DataElementIdentifier,
    elementValue: DataElementValue
  ) {
    const deviceSignedItems = this.structure.get(namespace)

    if (deviceSignedItems) {
      deviceSignedItems.deviceSignedItems.set(elementIdentifier, elementValue)
      this.markModified()
    } else {
      this.setDeviceNamespace(
        namespace,
        DeviceSignedItems.create({ deviceSignedItems: new Map([[elementIdentifier, elementValue]]) })
      )
    }
  }

  public static create(options: DeviceNamespacesOptions): DeviceNamespaces {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(options.deviceNamespaces)
  }
}
