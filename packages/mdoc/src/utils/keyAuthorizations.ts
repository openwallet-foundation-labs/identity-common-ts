import type { DataElementIdentifier } from '../mdoc/models/data-element-identifier'
import type { DeviceNamespaces } from '../mdoc/models/device-namespaces'
import type { KeyAuthorizations } from '../mdoc/models/key-authorizations'
import type { Namespace } from '../mdoc/models/namespace'

export type DeviceSignedElement = {
  namespace: Namespace
  elementIdentifier: DataElementIdentifier
}

/**
 * The data elements the mdoc authenticated through `DeviceNameSpaces`, flattened across namespaces.
 */
export const collectDeviceSignedElements = (deviceNamespaces?: DeviceNamespaces): Array<DeviceSignedElement> =>
  Array.from(deviceNamespaces?.deviceNamespaces ?? []).flatMap(([namespace, deviceSignedItems]) =>
    Array.from(deviceSignedItems.deviceSignedItems.keys()).map((elementIdentifier) => ({
      namespace,
      elementIdentifier,
    }))
  )

/**
 * Whether the device key is authorized to authenticate a device-signed element, either for its
 * whole namespace or for the data element itself (18013-5 9.1.2.4).
 */
export const isDeviceSignedElementAuthorized = (
  keyAuthorizations: KeyAuthorizations | undefined,
  { namespace, elementIdentifier }: DeviceSignedElement
) =>
  (keyAuthorizations?.namespaces?.includes(namespace) ||
    keyAuthorizations?.dataElements?.get(namespace)?.includes(elementIdentifier)) ??
  false

/**
 * The device-signed elements the device key is not authorized to authenticate.
 *
 * ISO/IEC 18013-5 9.1.3.4: "An mdoc shall only authenticate response data elements in
 * `DeviceNameSpaces` if the key it is using for mdoc authentication is authorized to authenticate
 * these elements in the `KeyAuthorizations` structure in the MSO. The mdoc reader shall validate
 * this authorization as part of validating the mdoc authentication." Authorization is given either
 * for a whole namespace or per data element (9.1.2.4), so both sides run this: the mdoc before it
 * signs or MACs a response, the mdoc reader after it decodes one.
 */
export const findUnauthorizedDeviceSignedElements = (options: {
  deviceNamespaces?: DeviceNamespaces
  keyAuthorizations?: KeyAuthorizations
}): Array<DeviceSignedElement> =>
  collectDeviceSignedElements(options.deviceNamespaces).filter(
    (element) => !isDeviceSignedElementAuthorized(options.keyAuthorizations, element)
  )

/**
 * A shared description of unauthorized elements, so the mdoc's error and the mdoc reader's failed
 * check name the same elements in the same way.
 */
export const describeUnauthorizedDeviceSignedElements = (unauthorized: Array<DeviceSignedElement>) =>
  `The device key is not authorized to authenticate ${unauthorized
    .map(({ namespace, elementIdentifier }) => `'${elementIdentifier}' in namespace '${namespace}'`)
    .join(', ')}`
