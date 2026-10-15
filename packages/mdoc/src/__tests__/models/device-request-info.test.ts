import { cborEncode, DataItem } from '@owf/cose'
import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { DeviceRequest } from '../../mdoc/models/device-request'
import { DeviceRequestInfo } from '../../mdoc/models/device-request-info'
import { DocRequest } from '../../mdoc/models/doc-request'
import { DocRequestInfo } from '../../mdoc/models/doc-request-info'
import { ItemsRequest } from '../../mdoc/models/items-request'

const MDL = 'org.iso.18013.5.1.mDL'
const MDL_NS = 'org.iso.18013.5.1'
const PID = 'eu.europa.ec.eudi.pid.1'

const itemsRequest = (docType: string, namespace: string, element: string, requestInfo?: Map<string, unknown>) => {
  const items = new Map<string, unknown>([
    ['docType', docType],
    ['nameSpaces', new Map([[namespace, new Map([[element, false]])]])],
  ])
  if (requestInfo) items.set('requestInfo', requestInfo)
  return new DataItem({ buffer: cborEncode(items) })
}

/** A device request as a reader using ISO/IEC TS 23220-4 7.2.1 sends it, built from raw CBOR. */
const encodedDeviceRequest = (options: { requestInfo?: Map<string, unknown>; deviceRequestInfo?: unknown } = {}) => {
  const request = new Map<string, unknown>([
    ['version', '1.0'],
    [
      'docRequests',
      [
        new Map([['itemsRequest', itemsRequest(MDL, MDL_NS, 'age_over_18', options.requestInfo)]]),
        new Map([['itemsRequest', itemsRequest(PID, PID, 'family_name')]]),
      ],
    ],
  ])
  if (options.deviceRequestInfo !== undefined) request.set('deviceRequestInfo', options.deviceRequestInfo)
  return cborEncode(request)
}

const requestInfo = new Map<string, unknown>([
  [
    'alternativeDataElements',
    [
      new Map<string, unknown>([
        ['requestedElement', [MDL_NS, 'age_over_18']],
        ['alternativeElementSets', [[[MDL_NS, 'age_in_years']], [[MDL_NS, 'birth_date']]]],
      ]),
    ],
  ],
  ['issuerIdentifiers', [hex.decode('0102030405')]],
  ['uniqueDocSetRequired', true],
  ['maximumResponseSize', 65536],
])

const deviceRequestInfo = new DataItem({
  buffer: cborEncode(
    new Map([
      [
        'useCases',
        [
          new Map<string, unknown>([
            ['mandatory', true],
            ['purposeHints', new Map([['org.example', 3]])],
            ['documentSets', [[0], [1]]],
          ]),
        ],
      ],
    ])
  ),
})

describe('ISO/IEC TS 23220-4 request information', () => {
  test('reads requestInfo and deviceRequestInfo', () => {
    const deviceRequest = DeviceRequest.decode(encodedDeviceRequest({ requestInfo, deviceRequestInfo }))

    const info = deviceRequest.docRequests[0].itemsRequest.requestInfo
    expect(info?.alternativeDataElements).toStrictEqual([
      {
        requestedElement: [MDL_NS, 'age_over_18'],
        alternativeElementSets: [[[MDL_NS, 'age_in_years']], [[MDL_NS, 'birth_date']]],
      },
    ])
    expect(info?.issuerIdentifiers).toStrictEqual([hex.decode('0102030405')])
    expect(info?.uniqueDocSetRequired).toBe(true)
    expect(info?.maximumResponseSize).toBe(65536)
    expect(deviceRequest.docRequests[1].itemsRequest.requestInfo).toBeUndefined()

    expect(deviceRequest.deviceRequestInfo?.useCases).toStrictEqual([
      { mandatory: true, purposeHints: new Map([['org.example', 3]]), documentSets: [[0], [1]] },
    ])
  })

  test('re-encodes the request byte for byte, as reader authentication signs it', () => {
    const bytes = encodedDeviceRequest({ requestInfo, deviceRequestInfo })

    expect(hex.encode(DeviceRequest.decode(bytes).encode())).toBe(hex.encode(bytes))
  })

  test('keeps keys it does not know', () => {
    const extended = new Map([...requestInfo, ['conditionalDataElements', [1, 2]]])
    const bytes = encodedDeviceRequest({ requestInfo: extended, deviceRequestInfo })

    expect(hex.encode(DeviceRequest.decode(bytes).encode())).toBe(hex.encode(bytes))
  })

  test('ignores, without failing the request, information that does not match the CDDL', () => {
    const malformed = new Map<string, unknown>([['alternativeDataElements', 'nope']])
    const garbledUseCases = new DataItem({ buffer: cborEncode(new Map([['useCases', 'nope']])) })
    const bytes = encodedDeviceRequest({ requestInfo: malformed, deviceRequestInfo: garbledUseCases })

    const deviceRequest = DeviceRequest.decode(bytes)

    expect(deviceRequest.docRequests).toHaveLength(2)
    expect(deviceRequest.docRequests[0].itemsRequest.requestInfo).toBeUndefined()
    expect(deviceRequest.deviceRequestInfo).toBeUndefined()
    expect(hex.encode(deviceRequest.encode())).toBe(hex.encode(bytes))
  })

  test('creates a request that reads back the same', () => {
    const deviceRequest = DeviceRequest.create({
      docRequests: [
        DocRequest.create({
          itemsRequest: ItemsRequest.create({
            docType: MDL,
            namespaces: { [MDL_NS]: { age_over_18: false } },
            requestInfo: DocRequestInfo.create({
              alternativeDataElements: [
                { requestedElement: [MDL_NS, 'age_over_18'], alternativeElementSets: [[[MDL_NS, 'birth_date']]] },
              ],
              issuerIdentifiers: [hex.decode('0a0b')],
            }),
          }),
        }),
        DocRequest.create({
          itemsRequest: ItemsRequest.create({ docType: PID, namespaces: { [PID]: { family_name: false } } }),
        }),
      ],
      deviceRequestInfo: DeviceRequestInfo.create({ useCases: [{ mandatory: true, documentSets: [[0], [1]] }] }),
    })

    const decoded = DeviceRequest.decode(deviceRequest.encode())

    expect(decoded.docRequests[0].itemsRequest.requestInfo?.alternativeDataElements).toStrictEqual([
      { requestedElement: [MDL_NS, 'age_over_18'], alternativeElementSets: [[[MDL_NS, 'birth_date']]] },
    ])
    expect(decoded.docRequests[0].itemsRequest.requestInfo?.issuerIdentifiers).toStrictEqual([hex.decode('0a0b')])
    expect(decoded.deviceRequestInfo?.useCases).toStrictEqual([{ mandatory: true, documentSets: [[0], [1]] }])
  })

  test('leaves a request without them as it was', () => {
    const bytes = encodedDeviceRequest()
    const deviceRequest = DeviceRequest.decode(bytes)

    expect(deviceRequest.deviceRequestInfo).toBeUndefined()
    expect(deviceRequest.docRequests[0].itemsRequest.requestInfo).toBeUndefined()
    expect(hex.encode(deviceRequest.encode())).toBe(hex.encode(bytes))
  })
})
