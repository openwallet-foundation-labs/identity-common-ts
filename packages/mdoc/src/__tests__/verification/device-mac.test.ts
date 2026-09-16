import nodeCrypto from 'node:crypto'
import { MacAlgorithm } from '@owf/cose'
import { describe, expect, test } from 'vitest'
import {
  CoseKey,
  DeviceRequest,
  DeviceResponse,
  DeviceSignedBuilder,
  DocRequest,
  Document,
  ItemsRequest,
  SessionTranscript,
  UnsupportedDeviceMacAlgorithmError,
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

/**
 * The ephemeral key pair of the mdoc reader, which the EMacKey is derived with.
 */
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

async function createMacResponse(sessionTranscript: SessionTranscript | Uint8Array, readerPublicKey: CoseKey) {
  return await DeviceResponse.createWithDeviceRequest(
    {
      deviceRequest,
      sessionTranscript,
      documents: [
        {
          issuerSigned: await createIssuerSigned(),
          docRequestIndex: 0,
          mac: { ephemeralKey: readerPublicKey, signingKey: deviceKey },
        },
      ],
    },
    mdocContext
  )
}

describe('device MAC (18013-5 9.1.3.5)', async () => {
  const sessionTranscript = await SessionTranscript.forIsoMdocDcApi(
    { encryptionInfoBase64Url: 'abc', origin: 'https://verifier.example.com' },
    mdocContext
  )

  test('a response authenticated with a device MAC verifies with the default callback', async () => {
    const { readerPrivateKey, readerPublicKey } = await createReaderEphemeralKey()
    const deviceResponse = DeviceResponse.decode((await createMacResponse(sessionTranscript, readerPublicKey)).encode())

    const deviceMac = deviceResponse.documents?.[0].deviceSigned.deviceAuth.deviceMac
    expect(deviceMac?.algorithm).toBe(MacAlgorithm.HS256)

    await expect(
      deviceResponse.verify(
        { sessionTranscript, ephemeralReaderKey: readerPrivateKey, trustedCertificates },
        mdocContext
      )
    ).resolves.toBeDefined()
  })

  test('a device MAC for another reader key FAILS', async () => {
    const { readerPublicKey } = await createReaderEphemeralKey()
    const { readerPrivateKey: otherReaderPrivateKey } = await createReaderEphemeralKey()
    const deviceResponse = await createMacResponse(sessionTranscript, readerPublicKey)

    await expect(
      deviceResponse.verify(
        { sessionTranscript, ephemeralReaderKey: otherReaderPrivateKey, trustedCertificates },
        mdocContext
      )
    ).rejects.toThrow('Device MAC must be valid')
  })

  test.each([
    ['SessionTranscript', () => sessionTranscript.encode()],
    ['SessionTranscriptBytes', () => sessionTranscript.encode({ asDataItem: true })],
  ])('the session transcript can be passed as %s', async (_, encodeSessionTranscript) => {
    const { readerPrivateKey, readerPublicKey } = await createReaderEphemeralKey()
    const deviceResponse = await createMacResponse(encodeSessionTranscript(), readerPublicKey)

    // Verified with the other encoding, as both identify the same session transcript.
    await expect(
      deviceResponse.verify(
        { sessionTranscript, ephemeralReaderKey: readerPrivateKey, trustedCertificates },
        mdocContext
      )
    ).resolves.toBeDefined()
    await expect(
      deviceResponse.verify(
        { sessionTranscript: encodeSessionTranscript(), ephemeralReaderKey: readerPrivateKey, trustedCertificates },
        mdocContext
      )
    ).resolves.toBeDefined()
  })

  test('DeviceSignedBuilder.tag only creates a device MAC with HMAC 256/256', async () => {
    const { readerPublicKey } = await createReaderEphemeralKey()

    await expect(
      new DeviceSignedBuilder(mdlDocType, mdocContext).tag({
        privateKey: deviceKey,
        publicKey: readerPublicKey,
        sessionTranscript,
        algorithm: MacAlgorithm.HS384,
      })
    ).rejects.toThrow(UnsupportedDeviceMacAlgorithmError)
  })

  test('DeviceSignedBuilder.tag creates a device MAC that verifies', async () => {
    const { readerPrivateKey, readerPublicKey } = await createReaderEphemeralKey()
    const issuerSigned = await createIssuerSigned()

    const deviceSigned = await new DeviceSignedBuilder(mdlDocType, mdocContext).tag({
      privateKey: deviceKey,
      publicKey: readerPublicKey,
      sessionTranscript,
      algorithm: MacAlgorithm.HS256,
    })

    const deviceResponse = DeviceResponse.createSimple({
      documents: [Document.create({ docType: mdlDocType, issuerSigned, deviceSigned })],
    })

    await expect(
      deviceResponse.verify(
        { sessionTranscript, ephemeralReaderKey: readerPrivateKey, trustedCertificates },
        mdocContext
      )
    ).resolves.toBeDefined()
  })
})
