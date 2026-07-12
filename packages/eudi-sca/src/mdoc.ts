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
  if (options.mdoc.deviceSigned.deviceNamespaces.deviceNamespaces.has(DEVICE_NAMESPACE_KEY)) {
    throw new Error(`Device namespace key '${DEVICE_NAMESPACE_KEY}' has already been set on the device namespaces`)
  }

  const responseClaims = await createResponseClaims(options, ctx)

  const scaDeviceSigneditems = new DeviceSignedItems(new Map(Object.entries(responseClaims)))

  // TODO: we need to sign this?
  options.mdoc.deviceSigned.deviceNamespaces.deviceNamespaces.set(DEVICE_NAMESPACE_KEY, scaDeviceSigneditems)

  return options.mdoc
}
