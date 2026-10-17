import { CborStructure, DataItem, TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import { DeviceRequestInfo } from './device-request-info'
import { DocRequest, type DocRequestEncodedStructure } from './doc-request'

const deviceRequestSchema = typedMap([
  ['version', z.string()],
  ['docRequests', z.array(z.instanceof(DocRequest))],
  ['deviceRequestInfo', z.instanceof(DeviceRequestInfo).exactOptional()],
] as const)

// Every document set of a use case points at doc requests of this device request.
const deviceRequestOutputSchema = deviceRequestSchema.out.superRefine((map, ctx) => {
  const docRequestCount = map.get('docRequests').length
  map.get('deviceRequestInfo')?.useCases?.forEach((useCase, useCaseIndex) => {
    for (const docRequestId of useCase.documentSets.flat()) {
      if (docRequestId >= docRequestCount) {
        ctx.addIssue({
          code: 'custom',
          path: ['deviceRequestInfo', 'useCases', useCaseIndex, 'documentSets'],
          message: `Doc request ${docRequestId} does not exist, the device request has ${docRequestCount}`,
        })
      }
    }
  })
})

export type DeviceRequestDecodedStructure = z.output<typeof deviceRequestSchema>
export type DeviceRequestEncodedStructure = z.input<typeof deviceRequestSchema>

export type DeviceRequestOptions = {
  version?: string
  docRequests: Array<DocRequest>
  deviceRequestInfo?: DeviceRequestInfo
}

export class DeviceRequest extends CborStructure<DeviceRequestEncodedStructure, DeviceRequestDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(deviceRequestSchema.in, deviceRequestOutputSchema, {
      decode: (input) => {
        const map: DeviceRequestDecodedStructure = TypedMap.fromMap(input)
        const docRequests = input.get('docRequests') as unknown[]

        map.set(
          'docRequests',
          docRequests.map((dr) => DocRequest.fromEncodedStructure(dr as DocRequestEncodedStructure))
        )

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
    const map: DeviceRequestDecodedStructure = new TypedMap([
      ['version', options.version ?? '1.0'],
      ['docRequests', options.docRequests],
    ])
    if (options.deviceRequestInfo) map.set('deviceRequestInfo', options.deviceRequestInfo)
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(map)
  }
}
