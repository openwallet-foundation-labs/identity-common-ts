import { CborStructure, DataItem, TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import { DeviceRequestInfo } from './device-request-info'
import { DocRequest, type DocRequestEncodedStructure } from './doc-request'

const deviceRequestSchema = typedMap([
  ['version', z.string()],
  ['docRequests', z.array(z.instanceof(DocRequest))],
  // A `DeviceRequestInfoBytes` that does not decode as ISO/IEC TS 23220-4 7.2.1.3.4 describes is
  // kept as the data item received, rather than failing the request.
  ['deviceRequestInfo', z.union([z.instanceof(DeviceRequestInfo), z.instanceof(DataItem)]).exactOptional()],
] as const)

export type DeviceRequestDecodedStructure = z.output<typeof deviceRequestSchema>
export type DeviceRequestEncodedStructure = z.input<typeof deviceRequestSchema>

export type DeviceRequestOptions = {
  version?: string
  docRequests: Array<DocRequest>
  deviceRequestInfo?: DeviceRequestInfo
}

export class DeviceRequest extends CborStructure<DeviceRequestEncodedStructure, DeviceRequestDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(deviceRequestSchema.in, deviceRequestSchema.out, {
      decode: (input) => {
        const map: DeviceRequestDecodedStructure = TypedMap.fromMap(input)
        const docRequests = input.get('docRequests') as unknown[]

        map.set(
          'docRequests',
          docRequests.map((dr) => DocRequest.fromEncodedStructure(dr as DocRequestEncodedStructure))
        )

        const deviceRequestInfo = input.get('deviceRequestInfo')
        if (deviceRequestInfo instanceof DataItem) {
          try {
            map.set('deviceRequestInfo', DeviceRequestInfo.fromDataItem(deviceRequestInfo))
          } catch {
            // Not a DeviceRequestInfo this version understands: left as is.
          }
        }

        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        map.set(
          'docRequests',
          output.get('docRequests').map((dr) => dr.encodedStructure)
        )

        const deviceRequestInfo = output.get('deviceRequestInfo')
        if (deviceRequestInfo instanceof DeviceRequestInfo) map.set('deviceRequestInfo', deviceRequestInfo.asDataItem)

        return map
      },
    })
  }

  public get version() {
    return this.structure.get('version')
  }

  public get docRequests() {
    return this.structure.get('docRequests')
  }

  /**
   * The `deviceRequestInfo` of ISO/IEC TS 23220-4 7.2.1.3.4, when present and readable. One that
   * does not decode is not returned, and stays in the encoded device request as received.
   */
  public get deviceRequestInfo(): DeviceRequestInfo | undefined {
    const deviceRequestInfo = this.structure.get('deviceRequestInfo')
    return deviceRequestInfo instanceof DeviceRequestInfo ? deviceRequestInfo : undefined
  }

  public static create(options: DeviceRequestOptions): DeviceRequest {
    const map: DeviceRequestDecodedStructure = new TypedMap([
      ['version', options.version ?? '1.0'],
      ['docRequests', options.docRequests],
    ])
    if (options.deviceRequestInfo) map.set('deviceRequestInfo', options.deviceRequestInfo)
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(map)
  }
}
