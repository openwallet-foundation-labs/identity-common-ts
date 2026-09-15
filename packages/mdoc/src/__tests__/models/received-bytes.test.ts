import { cborEncode, DataItem, ProtectedHeaders, RegisteredCwtHeaderClaimKey, UnprotectedHeaders } from '@owf/cose'
import { compareBytes, concatBytes, hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import {
  CoseKey,
  DeviceEngagement,
  DeviceNamespaces,
  DeviceRequest,
  DeviceResponse,
  DeviceSignature,
  DeviceSignedItems,
  EReaderKey,
  Holder,
  ItemsRequest,
  ReaderAuth,
  SessionTranscript,
  SignatureAlgorithm,
} from '../..'
import { DEVICE_JWK_PRIVATE } from '../config'
import { mdocContext } from '../context'
import { createIssuerSigned, issuerCertificate, mdlDocType, mdlNamespace } from '../iso-mdoc-dc-api/fixtures'
import { createReaderCertificate } from '../iso-mdoc-dc-api/reader-certificate'

/**
 * An indefinite-length map of already encoded entries. This library never encodes one, so a structure
 * that is re-encoded instead of embedded as received gets other bytes.
 */
const indefiniteMap = (...entries: Array<[unknown, Uint8Array]>) =>
  concatBytes(Uint8Array.of(0xbf), ...entries.flatMap(([key, value]) => [cborEncode(key), value]), Uint8Array.of(0xff))

const dataItem = (bytes: Uint8Array) => cborEncode(DataItem.fromBuffer(bytes))

const itemsRequestBytes = indefiniteMap(
  ['docType', cborEncode(mdlDocType)],
  ['nameSpaces', indefiniteMap([mdlNamespace, indefiniteMap(['family_name', cborEncode(false)])])]
)

describe('received bytes are used as received (18013-5 8.1)', async () => {
  const sessionTranscript = await SessionTranscript.forIsoMdocDcApi(
    { encryptionInfoBase64Url: 'abc', origin: 'https://verifier.example.com' },
    mdocContext
  )

  test('the fixtures do not encode the way this library does', () => {
    const itemsRequest = ItemsRequest.create({
      docType: mdlDocType,
      namespaces: { [mdlNamespace]: { family_name: false } },
    })
    expect(compareBytes(itemsRequest.encode(), itemsRequestBytes)).toBe(false)
  })

  test('a decoded structure encodes as received, also from tagged bytes', () => {
    expect(hex.encode(ItemsRequest.decode(itemsRequestBytes).encode())).toBe(hex.encode(itemsRequestBytes))
    expect(hex.encode(ItemsRequest.decode(itemsRequestBytes).encode({ asDataItem: true }))).toBe(
      hex.encode(dataItem(itemsRequestBytes))
    )
    expect(hex.encode(ItemsRequest.decode(dataItem(itemsRequestBytes)).encode())).toBe(hex.encode(itemsRequestBytes))
  })

  test('the device engagement and reader key are embedded in the session transcript as received', () => {
    const deviceEngagementBytes = hex.decode(
      'bf0063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc670281830201a300f401f50b5045efef742b2c4837a9a3b0e1d05a6917ff'
    )
    const eReaderKeyBytes = hex.decode(
      'bf010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67ff'
    )

    const qrSessionTranscript = SessionTranscript.forQrHandover({
      deviceEngagement: DeviceEngagement.decode(deviceEngagementBytes),
      eReaderKey: EReaderKey.decode(eReaderKeyBytes),
    })

    expect(hex.encode(qrSessionTranscript.encode())).toBe(
      hex.encode(cborEncode([DataItem.fromBuffer(deviceEngagementBytes), DataItem.fromBuffer(eReaderKeyBytes), null]))
    )
  })

  test('reader auth over the ItemsRequestBytes as received verifies', async () => {
    const { readerKey, readerCertificate } = await createReaderCertificate()

    const readerAuthenticationBytes = cborEncode([
      'ReaderAuthentication',
      sessionTranscript.encodedStructure,
      DataItem.fromBuffer(itemsRequestBytes),
    ])

    const unprotectedHeaders = UnprotectedHeaders.create({})
    unprotectedHeaders.headers?.set(RegisteredCwtHeaderClaimKey.X5Chain, readerCertificate)
    const readerAuth = await ReaderAuth.create({
      protectedHeaders: ProtectedHeaders.create({
        protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
      }),
      unprotectedHeaders,
      payload: null,
    }).sign({ signingKey: readerKey, detachedPayload: dataItem(readerAuthenticationBytes) }, mdocContext.cose.sign1)

    const deviceRequestBytes = cborEncode(
      new Map<string, unknown>([
        ['version', '1.0'],
        [
          'docRequests',
          [
            new Map<string, unknown>([
              ['itemsRequest', DataItem.fromBuffer(itemsRequestBytes)],
              ['readerAuth', readerAuth.encodedStructure],
            ]),
          ],
        ],
      ])
    )

    await expect(
      Holder.verifyDeviceRequest(
        {
          deviceRequest: deviceRequestBytes,
          sessionTranscript,
          trustedCertificates: [readerCertificate],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()

    // Re-encoding the decoded device request keeps the bytes the reader signed.
    expect(hex.encode(DeviceRequest.decode(deviceRequestBytes).encode())).toBe(hex.encode(deviceRequestBytes))
  })

  test('device auth over the DeviceNameSpacesBytes as received verifies', async () => {
    const deviceNamespacesBytes = indefiniteMap()
    const deviceKey = CoseKey.fromJwk(DEVICE_JWK_PRIVATE)

    const deviceAuthenticationBytes = cborEncode([
      'DeviceAuthentication',
      sessionTranscript.encodedStructure,
      mdlDocType,
      DataItem.fromBuffer(deviceNamespacesBytes),
    ])

    const deviceSignature = await DeviceSignature.create({
      protectedHeaders: ProtectedHeaders.create({
        protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
      }),
      unprotectedHeaders: UnprotectedHeaders.create({}),
      payload: null,
    }).sign({ signingKey: deviceKey, detachedPayload: dataItem(deviceAuthenticationBytes) }, mdocContext.cose.sign1)

    const issuerSigned = await createIssuerSigned()
    const deviceResponseBytes = cborEncode(
      new Map<string, unknown>([
        ['version', '1.0'],
        [
          'documents',
          [
            new Map<string, unknown>([
              ['docType', mdlDocType],
              ['issuerSigned', issuerSigned.encodedStructure],
              [
                'deviceSigned',
                new Map<string, unknown>([
                  ['nameSpaces', DataItem.fromBuffer(deviceNamespacesBytes)],
                  ['deviceAuth', new Map([['deviceSignature', deviceSignature.encodedStructure]])],
                ]),
              ],
            ]),
          ],
        ],
        ['status', 0],
      ])
    )

    const deviceResponse = DeviceResponse.decode(deviceResponseBytes)
    await expect(
      deviceResponse.verify(
        {
          // As SessionTranscriptBytes, which is the same session transcript.
          sessionTranscript: sessionTranscript.encode({ asDataItem: true }),
          trustedCertificates: [{ issuance: [issuerCertificate] }],
        },
        mdocContext
      )
    ).resolves.toBeDefined()

    // Forwarding the decoded device response keeps the bytes the device signed.
    expect(hex.encode(deviceResponse.encode())).toBe(hex.encode(deviceResponseBytes))
  })
})

describe('OriginalBytesCborStructure', () => {
  const itemsRequestBytes = hex.decode(
    'bf67646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6a6e616d65537061636573bf716f72672e69736f2e31383031332e352e31bf6b66616d696c795f6e616d65f4ffffff'
  )

  test('asDataItem embeds the bytes the structure was received as', () => {
    const itemsRequest = ItemsRequest.decode(itemsRequestBytes)

    expect(hex.encode(itemsRequest.originalBytes ?? new Uint8Array())).toBe(hex.encode(itemsRequestBytes))
    expect(hex.encode(itemsRequest.asDataItem.buffer)).toBe(hex.encode(itemsRequestBytes))
  })

  test('setting an entry of the structure re-encodes it', () => {
    const itemsRequest = ItemsRequest.decode(itemsRequestBytes)
    itemsRequest.decodedStructure.set('docType', 'org.example.other')

    expect(itemsRequest.originalBytes).toBeUndefined()
    expect(ItemsRequest.decode(itemsRequest.encode()).docType).toBe('org.example.other')
  })

  test('markModified re-encodes a structure that was changed in place', () => {
    const itemsRequest = ItemsRequest.decode(itemsRequestBytes)
    itemsRequest.namespaces.get(mdlNamespace)?.set('given_name', true)
    expect(hex.encode(itemsRequest.encode())).toBe(hex.encode(itemsRequestBytes))

    itemsRequest.markModified()
    expect(ItemsRequest.decode(itemsRequest.encode()).namespaces.get(mdlNamespace)?.get('given_name')).toBe(true)
  })

  test('setting a device namespace or element re-encodes the device namespaces', () => {
    const deviceNamespacesBytes = indefiniteMap([mdlNamespace, indefiniteMap(['family_name', cborEncode('Doe')])])

    const withElement = DeviceNamespaces.decode(deviceNamespacesBytes)
    expect(hex.encode(withElement.encode())).toBe(hex.encode(deviceNamespacesBytes))
    withElement.setDeviceSignedElement(mdlNamespace, 'given_name', 'John')
    expect(withElement.originalBytes).toBeUndefined()
    expect(
      DeviceNamespaces.decode(withElement.encode())
        .getDeviceNamespace(mdlNamespace)
        ?.deviceSignedItems.get('given_name')
    ).toBe('John')

    const withNamespace = DeviceNamespaces.decode(deviceNamespacesBytes)
    withNamespace.setDeviceNamespace(
      'org.example',
      DeviceSignedItems.create({ deviceSignedItems: new Map([['element', true]]) })
    )
    expect(withNamespace.originalBytes).toBeUndefined()
    expect(
      DeviceNamespaces.decode(withNamespace.encode())
        .getDeviceNamespace('org.example')
        ?.deviceSignedItems.get('element')
    ).toBe(true)
  })
})
