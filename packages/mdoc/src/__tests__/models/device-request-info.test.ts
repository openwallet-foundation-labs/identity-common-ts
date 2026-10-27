import { cborDecode, cborEncode, DataItem } from '@owf/cose'
import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { DeviceRequest } from '../../mdoc/models/device-request'
import { DeviceRequestInfo } from '../../mdoc/models/device-request-info'
import { DocRequest } from '../../mdoc/models/doc-request'
import { ItemsRequest } from '../../mdoc/models/items-request'

const MDL = 'org.iso.18013.5.1.mDL'
const MDL_NS = 'org.iso.18013.5.1'
const PID = 'eu.europa.ec.eudi.pid.1'

const itemsRequest = (docType: string, namespace: string, element: string, requestInfo?: unknown) => {
  const items = new Map<string, unknown>([
    ['docType', docType],
    ['nameSpaces', new Map([[namespace, new Map([[element, false]])]])],
  ])
  if (requestInfo !== undefined) items.set('requestInfo', requestInfo)
  return new DataItem({ buffer: cborEncode(items) })
}

/** A device request as a reader using ISO/IEC TS 23220-4 7.2.1 sends it, built from raw CBOR. */
const encodedDeviceRequest = (options: { requestInfo?: unknown; deviceRequestInfo?: unknown } = {}) => {
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
    expect(info?.alternativeDataElements).toHaveLength(1)
    expect(info?.alternativeDataElements?.[0].requestedElement).toStrictEqual([MDL_NS, 'age_over_18'])
    expect(info?.alternativeDataElements?.[0].alternativeElementSets).toStrictEqual([
      [[MDL_NS, 'age_in_years']],
      [[MDL_NS, 'birth_date']],
    ])
    expect(info?.issuerIdentifiers).toStrictEqual([hex.decode('0102030405')])
    expect(info?.uniqueDocSetRequired).toBe(true)
    expect(info?.maximumResponseSize).toBe(65536)
    expect(deviceRequest.docRequests[1].itemsRequest.requestInfo).toBeUndefined()

    const useCases = deviceRequest.deviceRequestInfo?.useCases
    expect(useCases).toHaveLength(1)
    expect(useCases?.[0].mandatory).toBe(true)
    expect(useCases?.[0].purposeHints).toStrictEqual(new Map([['org.example', 3]]))
    expect(useCases?.[0].documentSets).toStrictEqual([[0], [1]])
  })

  test('re-encodes the request byte for byte, as reader authentication signs it', () => {
    const bytes = encodedDeviceRequest({ requestInfo, deviceRequestInfo })

    expect(hex.encode(DeviceRequest.decode(bytes).encode())).toBe(hex.encode(bytes))
  })

  test('keeps keys it does not know, nested ones included', () => {
    const extended = new Map<string, unknown>([
      [
        'alternativeDataElements',
        [
          new Map<string, unknown>([
            ['requestedElement', [MDL_NS, 'age_over_18']],
            ['alternativeElementSets', [[[MDL_NS, 'birth_date']]]],
            ['rfu', 1],
          ]),
        ],
      ],
      ['conditionalDataElements', [1, 2]],
    ])
    const extendedUseCases = new DataItem({
      buffer: cborEncode(
        new Map<string, unknown>([
          [
            'useCases',
            [
              new Map<string, unknown>([
                ['mandatory', false],
                ['documentSets', [[0, 1]]],
                ['rfu', 'x'],
              ]),
            ],
          ],
          ['rfu', true],
        ])
      ),
    })
    const bytes = encodedDeviceRequest({ requestInfo: extended, deviceRequestInfo: extendedUseCases })

    const deviceRequest = DeviceRequest.decode(bytes)

    expect(deviceRequest.deviceRequestInfo?.useCases?.[0].documentSets).toStrictEqual([[0, 1]])
    expect(hex.encode(deviceRequest.encode())).toBe(hex.encode(bytes))
  })

  test.each([
    ['alternativeDataElements is not an array', { requestInfo: new Map([['alternativeDataElements', 'nope']]) }],
    [
      'an alternative lacks its requested element',
      {
        requestInfo: new Map([
          ['alternativeDataElements', [new Map([['alternativeElementSets', [[[MDL_NS, 'birth_date']]]]])]],
        ]),
      },
    ],
    ['issuerIdentifiers holds a string', { requestInfo: new Map([['issuerIdentifiers', ['abc']]]) }],
    ['requestInfo is not a map', { requestInfo: 'nope' }],
    [
      'useCases is not an array',
      { deviceRequestInfo: new DataItem({ buffer: cborEncode(new Map([['useCases', 'nope']])) }) },
    ],
    [
      'a use case lacks mandatory',
      {
        deviceRequestInfo: new DataItem({
          buffer: cborEncode(new Map([['useCases', [new Map([['documentSets', [[0]]]])]]])),
        }),
      },
    ],
    ['deviceRequestInfo is not tagged', { deviceRequestInfo: new Map([['useCases', []]]) }],
  ])('fails to decode when %s', (_, options) => {
    expect(() => DeviceRequest.decode(encodedDeviceRequest(options as never))).toThrow()
  })

  test('fails to decode a document set that points past the doc requests', () => {
    const outOfRange = new DataItem({
      buffer: cborEncode(
        new Map([
          [
            'useCases',
            [
              new Map<string, unknown>([
                ['mandatory', true],
                ['documentSets', [[0], [2]]],
              ]),
            ],
          ],
        ])
      ),
    })

    expect(() => DeviceRequest.decode(encodedDeviceRequest({ deviceRequestInfo: outOfRange }))).toThrow(
      /Doc request 2 does not exist, the device request has 2/
    )
  })

  test('creates a request that reads back the same', () => {
    const deviceRequest = DeviceRequest.create({
      docRequests: [
        DocRequest.create({
          itemsRequest: ItemsRequest.create({
            docType: MDL,
            namespaces: { [MDL_NS]: { age_over_18: false } },
            requestInfo: {
              alternativeDataElements: [
                { requestedElement: [MDL_NS, 'age_over_18'], alternativeElementSets: [[[MDL_NS, 'birth_date']]] },
              ],
              issuerIdentifiers: [hex.decode('0a0b')],
            },
          }),
        }),
        DocRequest.create({
          itemsRequest: ItemsRequest.create({ docType: PID, namespaces: { [PID]: { family_name: false } } }),
        }),
      ],
      deviceRequestInfo: { useCases: [{ mandatory: true, documentSets: [[0], [1]] }] },
    })

    const decoded = DeviceRequest.decode(deviceRequest.encode())

    expect(decoded.version).toBe('1.1')

    const alternatives = decoded.docRequests[0].itemsRequest.requestInfo?.alternativeDataElements
    expect(alternatives?.[0].requestedElement).toStrictEqual([MDL_NS, 'age_over_18'])
    expect(alternatives?.[0].alternativeElementSets).toStrictEqual([[[MDL_NS, 'birth_date']]])
    expect(decoded.docRequests[0].itemsRequest.requestInfo?.issuerIdentifiers).toStrictEqual([hex.decode('0a0b')])
    expect(decoded.deviceRequestInfo?.useCases?.[0].mandatory).toBe(true)
    expect(decoded.deviceRequestInfo?.useCases?.[0].documentSets).toStrictEqual([[0], [1]])
  })

  test('reports each missing doc request of a use case once', () => {
    const outOfRange = new DataItem({
      buffer: cborEncode(
        new Map([
          [
            'useCases',
            [
              new Map<string, unknown>([
                ['mandatory', true],
                ['documentSets', [[5], [5, 6], [5]]],
              ]),
            ],
          ],
        ])
      ),
    })

    expect(() => DeviceRequest.decode(encodedDeviceRequest({ deviceRequestInfo: outOfRange }))).toThrow(
      /^[^✖]*✖ Doc request 5, 6 do not exist, the device request has 2[^✖]*$/
    )
  })

  test('reads integers an encoder wrote in more bytes than they need', () => {
    const wide = new Map<string, unknown>([['maximumResponseSize', BigInt(65536)]])
    const wideUseCases = new DataItem({
      buffer: cborEncode(
        new Map([
          [
            'useCases',
            [
              new Map<string, unknown>([
                ['mandatory', true],
                ['purposeHints', new Map([['org.iso.jtc1.sc17', BigInt(3)]])],
                ['documentSets', [[BigInt(0)], [BigInt(1)]]],
              ]),
            ],
          ],
        ])
      ),
    })
    const bytes = encodedDeviceRequest({ requestInfo: wide, deviceRequestInfo: wideUseCases })
    // cbor-x decodes an integer written in 8 bytes as a bigint, whatever its value.
    expect(typeof (cborDecode(cborEncode(wide)) as Map<string, unknown>).get('maximumResponseSize')).toBe('bigint')

    const deviceRequest = DeviceRequest.decode(bytes)

    expect(deviceRequest.docRequests[0].itemsRequest.requestInfo?.maximumResponseSize).toBe(65536)
    expect(deviceRequest.deviceRequestInfo?.useCases?.[0].purposeHints).toStrictEqual(
      new Map([['org.iso.jtc1.sc17', 3]])
    )
    expect(deviceRequest.deviceRequestInfo?.useCases?.[0].documentSets).toStrictEqual([[0], [1]])
    expect(hex.encode(deviceRequest.encode())).toBe(hex.encode(bytes))
  })

  test('fails to decode a device request without doc requests', () => {
    const bytes = cborEncode(new Map([['version', '1.0']]))

    expect(() => DeviceRequest.decode(bytes)).toThrow(/Expected key 'docRequests' to be defined/)
  })

  test('creates version 1.1 with deviceRequestInfo, as 18013-5 asks, and 1.0 without', () => {
    const docRequests = [
      DocRequest.create({
        itemsRequest: ItemsRequest.create({ docType: PID, namespaces: { [PID]: { family_name: false } } }),
      }),
    ]
    const useCases = { useCases: [{ mandatory: true, documentSets: [[0]] }] }

    expect(DeviceRequest.create({ docRequests }).version).toBe('1.0')
    expect(DeviceRequest.create({ docRequests, deviceRequestInfo: useCases }).version).toBe('1.1')
    expect(DeviceRequest.create({ docRequests, deviceRequestInfo: useCases, version: '1.0' }).version).toBe('1.0')
  })

  test('refuses to create a document set that points past the doc requests', () => {
    expect(() =>
      DeviceRequest.create({
        docRequests: [
          DocRequest.create({
            itemsRequest: ItemsRequest.create({ docType: PID, namespaces: { [PID]: { family_name: false } } }),
          }),
        ],
        deviceRequestInfo: DeviceRequestInfo.create({ useCases: [{ mandatory: true, documentSets: [[1]] }] }),
      })
    ).toThrow(/Doc request 1 does not exist, the device request has 1/)
  })

  test('leaves a request without them as it was', () => {
    const bytes = encodedDeviceRequest()
    const deviceRequest = DeviceRequest.decode(bytes)

    expect(deviceRequest.deviceRequestInfo).toBeUndefined()
    expect(deviceRequest.docRequests[0].itemsRequest.requestInfo).toBeUndefined()
    expect(hex.encode(deviceRequest.encode())).toBe(hex.encode(bytes))
  })
})
