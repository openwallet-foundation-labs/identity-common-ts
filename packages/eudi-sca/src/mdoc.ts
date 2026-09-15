import type { Hasher } from '@owf/identity-common'
import { DeviceSignedItems, type Document } from '@owf/mdoc'
import { type CreateResponseClaimsOptions, createResponseClaims } from './responseClaims'

const DEVICE_NAMESPACE_KEY = 'eu.europa.ec.eudi.sca.1'

export type CreateMdocDeviceResponseOptions = CreateResponseClaimsOptions & {
  mdoc: Document
}

export const createMdocDeviceResponse = async (
  options: CreateMdocDeviceResponseOptions,
  ctx: { hasher: Hasher; getRandomValues: (length: number) => Uint8Array }
) => {
  const deviceNamespaces = options.mdoc.deviceSigned.deviceNamespaces
  if (deviceNamespaces.getDeviceNamespace(DEVICE_NAMESPACE_KEY)) {
    throw new Error(`Device namespace key '${DEVICE_NAMESPACE_KEY}' has already been set on the device namespaces`)
  }

  const responseClaims = await createResponseClaims(options, ctx)

  const scaDeviceSignedItems = DeviceSignedItems.create({ deviceSignedItems: new Map(Object.entries(responseClaims)) })

  // TODO: we need to sign this?
  // `setDeviceNamespace` drops the bytes the device namespaces were decoded from, so the namespace is encoded
  deviceNamespaces.setDeviceNamespace(DEVICE_NAMESPACE_KEY, scaDeviceSignedItems)

  return options.mdoc
}
