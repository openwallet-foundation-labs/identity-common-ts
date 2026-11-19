import nodeCrypto from 'node:crypto'
import { hex } from '@owf/identity-common'
import { describe, expect, test, vi } from 'vitest'
import {
  CoseKey,
  DeviceRequest,
  DeviceResponse,
  DocRequest,
  EReaderKey,
  IssuerAuth,
  IssuerSigned,
  IssuerSignedItem,
  ItemsRequest,
  type MdocContext,
  SessionTranscript,
} from '../..'
import { DEVICE_JWK_PRIVATE } from '../config'
import { mdocContext } from '../context'
import { createIssuerSigned, issuerCertificate, mdlDocType, mdlNamespace } from '../iso-mdoc-dc-api/fixtures'

const deviceKey = CoseKey.fromJwk(DEVICE_JWK_PRIVATE)
const trustedCertificates = [{ issuance: [issuerCertificate] }]

const deviceRequest = DeviceRequest.create({
  docRequests: [
    DocRequest.create({
      itemsRequest: ItemsRequest.create({ docType: mdlDocType, namespaces: { [mdlNamespace]: { family_name: true } } }),
    }),
  ],
})

async function createReaderEphemeralKey() {
  const { privateKey } = (await nodeCrypto.webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ])) as nodeCrypto.webcrypto.CryptoKeyPair
  const { kty, crv, x, y, d } = (await nodeCrypto.webcrypto.subtle.exportKey('jwk', privateKey)) as Record<
    string,
    unknown
  >

  return {
    readerPrivateKey: CoseKey.fromJwk({ kty, crv, x, y, d }),
    readerPublicKey: CoseKey.fromJwk({ kty, crv, x, y }),
  }
}

describe('work done once per flow', () => {
  test('the mobile security object is decoded once, and again when the payload is replaced', async () => {
    const { issuerAuth } = await createIssuerSigned()
    const mobileSecurityObject = issuerAuth.mobileSecurityObject
    expect(issuerAuth.mobileSecurityObject).toBe(mobileSecurityObject)

    const { issuerAuth: other } = await createIssuerSigned({ docType: 'org.example.other' })
    issuerAuth.decodedStructure.payload = other.payload
    expect(issuerAuth.mobileSecurityObject.docType).toBe('org.example.other')

    // The decoded instance is a new one, which has no mobile security object yet
    expect(IssuerAuth.decode(issuerAuth.encode()).mobileSecurityObject.docType).toBe('org.example.other')
  })

  test('verifying issuer signed looks up the certificate data once', async () => {
    const issuerSigned = IssuerSigned.decode(
      (await createIssuerSigned({ claims: { issuing_country: 'XX', issuing_jurisdiction: 'XX-YY' } })).encode()
    )

    const x509: MdocContext['x509'] = {
      ...mdocContext.x509,
      getCertificateData: vi.fn(mdocContext.x509.getCertificateData),
    }

    await issuerSigned.verify({ trustedCertificates, verificationCallback: () => {} }, { ...mdocContext, x509 })

    expect(x509.getCertificateData).toHaveBeenCalledTimes(1)
  })

  test('a built issuer signed item keeps the bytes of its first encode until it is changed', () => {
    const item = IssuerSignedItem.fromOptions({
      digestId: 0,
      random: new Uint8Array(32).fill(7),
      elementIdentifier: 'given_name',
      elementValue: 'Alice',
    })

    const bytes = item.encode()
    expect(item.encode()).toBe(bytes)
    expect(item.asDataItem.buffer).toBe(bytes)
    expect(item.originalBytes).toBeUndefined()

    item.decodedStructure.set('elementValue', 'Bob')
    expect(IssuerSignedItem.decode(item.encode()).elementValue).toBe('Bob')
  })

  test.each([
    ['SessionTranscript', (sessionTranscript: SessionTranscript) => sessionTranscript.encode()],
    [
      'SessionTranscriptBytes',
      (sessionTranscript: SessionTranscript) => sessionTranscript.encode({ asDataItem: true }),
    ],
  ])('a session transcript passed as %s is decoded once per response', async (_, encode) => {
    const sessionTranscript = await SessionTranscript.forIsoMdocDcApi(
      { encryptionInfoBase64Url: 'abc', origin: 'https://verifier.example.com' },
      mdocContext
    )
    const sessionTranscriptBytes = encode(sessionTranscript)
    const { readerPrivateKey, readerPublicKey } = await createReaderEphemeralKey()
    const document = {
      issuerSigned: await createIssuerSigned(),
      docRequestIndex: 0,
      mac: { ephemeralKey: readerPublicKey, signingKey: deviceKey },
    }

    const decode = vi.spyOn(SessionTranscript, 'decode')
    try {
      const deviceResponse = await DeviceResponse.createWithDeviceRequest(
        { deviceRequest, sessionTranscript: sessionTranscriptBytes, documents: [document, document] },
        mdocContext
      )
      expect(decode).toHaveBeenCalledTimes(1)

      await deviceResponse.verify(
        { sessionTranscript: sessionTranscriptBytes, ephemeralReaderKey: readerPrivateKey, trustedCertificates },
        mdocContext
      )
      expect(decode).toHaveBeenCalledTimes(2)

      // The same bytes are authenticated as for the decoded session transcript
      await expect(
        deviceResponse.verify(
          { sessionTranscript, ephemeralReaderKey: readerPrivateKey, trustedCertificates },
          mdocContext
        )
      ).resolves.toBeDefined()
    } finally {
      decode.mockRestore()
    }
  })

  test('a decoded structure keeps the bytes it was received as, with or without tag 24', () => {
    const jwk = { kty: 'EC', crv: 'P-256', x: DEVICE_JWK_PRIVATE.x, y: DEVICE_JWK_PRIVATE.y }
    const bytes = EReaderKey.fromJwk(jwk).encode()
    const taggedBytes = EReaderKey.fromJwk(jwk).encode({ asDataItem: true })

    expect(hex.encode(EReaderKey.decode(bytes).originalBytes ?? new Uint8Array())).toBe(hex.encode(bytes))
    expect(hex.encode(EReaderKey.decode(taggedBytes).originalBytes ?? new Uint8Array())).toBe(hex.encode(bytes))

    const itemBytes = IssuerSignedItem.fromOptions({
      digestId: 1,
      random: new Uint8Array(16),
      elementIdentifier: 'a',
      elementValue: 1,
    })
    expect(hex.encode(IssuerSignedItem.decode(itemBytes.encode({ asDataItem: true })).encode())).toBe(
      hex.encode(itemBytes.encode())
    )
  })
})
