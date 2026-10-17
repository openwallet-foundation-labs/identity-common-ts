import { CborStructure, DataItem, TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import { DeviceRequestInfo, type DeviceRequestInfoOptions } from './device-request-info'
import { DocRequest, type DocRequestEncodedStructure } from './doc-request'

const deviceRequestSchema = typedMap([
  ['version', z.string()],
  ['docRequests', z.array(z.instanceof(DocRequest))],
  ['deviceRequestInfo', z.instanceof(DeviceRequestInfo).exactOptional()],
] as const)

// Every document set of a use case points at doc requests of this device request.
const deviceRequestOutputSchema = deviceRequestSchema.out.superRefine((map, ctx) => {
  // A missing or invalid docRequests is reported by the schema itself.
  const docRequests: unknown = map.get('docRequests')
  if (!Array.isArray(docRequests)) return
  const docRequestCount = docRequests.length
  map.get('deviceRequestInfo')?.useCases?.forEach((useCase, useCaseIndex) => {
    const missing = Array.from(new Set(useCase.documentSets.flat())).filter((id) => id >= docRequestCount)
    if (missing.length === 0) return
    ctx.addIssue({
      code: 'custom',
      path: ['deviceRequestInfo', 'useCases', useCaseIndex, 'documentSets'],
      message: `Doc request ${missing.join(', ')} ${missing.length === 1 ? 'does' : 'do'} not exist, the device request has ${docRequestCount}`,
    })
  })
})

export type DeviceRequestDecodedStructure = z.output<typeof deviceRequestSchema>
export type DeviceRequestEncodedStructure = z.input<typeof deviceRequestSchema>

export type DeviceRequestOptions = {
  /**
   * Defaults to `'1.1'` when `deviceRequestInfo` is given and to `'1.0'` otherwise, as the second
   * edition of ISO/IEC 18013-5 asks (10.2.2).
   */
  version?: string
  docRequests: Array<DocRequest>
  deviceRequestInfo?: DeviceRequestInfo | DeviceRequestInfoOptions
}

export class DeviceRequest extends CborStructure<DeviceRequestEncodedStructure, DeviceRequestDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(deviceRequestSchema.in, deviceRequestOutputSchema, {
      decode: (input) => {
        const map: DeviceRequestDecodedStructure = TypedMap.fromMap(input)
        // Anything but an array is left for the schema to reject.
        const docRequests = input.get('docRequests')
        if (Array.isArray(docRequests)) {
          map.set(
            'docRequests',
            docRequests.map((dr) => DocRequest.fromEncodedStructure(dr as DocRequestEncodedStructure))
          )
        }

        // Anything but a data item is left for the schema to reject.
        const deviceRequestInfo = input.get('deviceRequestInfo')
        if (deviceRequestInfo instanceof DataItem) {
          map.set('deviceRequestInfo', DeviceRequestInfo.fromDataItem(deviceRequestInfo))
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
        if (deviceRequestInfo) map.set('deviceRequestInfo', deviceRequestInfo.asDataItem)

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
   * The `deviceRequestInfo` of ISO/IEC TS 23220-4 7.2.1.3.4.
   */
  public get deviceRequestInfo() {
    return this.structure.get('deviceRequestInfo')
  }

  public static create(options: DeviceRequestOptions): DeviceRequest {
    const deviceRequestInfo =
      options.deviceRequestInfo instanceof DeviceRequestInfo || options.deviceRequestInfo === undefined
        ? options.deviceRequestInfo
        : DeviceRequestInfo.create(options.deviceRequestInfo)

    const map: DeviceRequestDecodedStructure = new TypedMap([
      ['version', options.version ?? (deviceRequestInfo ? '1.1' : '1.0')],
      ['docRequests', options.docRequests],
    ])
    if (deviceRequestInfo) map.set('deviceRequestInfo', deviceRequestInfo)
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(map)
  }
}
