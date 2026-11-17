import nodeCrypto from 'node:crypto'
import { p256 } from '@noble/curves/nist.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { MacAlgorithm } from '@owf/cose'
import { hex, stringToBytes } from '@owf/identity-common'
import { hkdf } from '@panva/hkdf'
import { describe, expect, test } from 'vitest'
import {
  CoseKey,
  Curve,
  cborEncode,
  DeviceAuth,
  DeviceAuthentication,
  DeviceMac,
  DeviceMacNotSupportedError,
  DeviceNamespaces,
  DeviceRequest,
  DeviceResponse,
  DeviceSignedBuilder,
  DocRequest,
  Document,
  ItemsRequest,
  KeyType,
  type MdocContext,
  SessionTranscript,
  UnsupportedDeviceMacAlgorithmError,
} from '../..'
import { DEVICE_JWK_PRIVATE, DEVICE_JWK_PUBLIC } from '../config'
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
          mac: { deviceKey, ephemeralReaderKey: readerPublicKey },
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

  test('a device MAC needs crypto.deviceMac in the context', async () => {
    const { readerPublicKey } = await createReaderEphemeralKey()
    const { deviceMac: _, ...crypto } = mdocContext.crypto

    await expect(
      new DeviceSignedBuilder(mdlDocType, { ...mdocContext, crypto }).tag({
        deviceKey,
        ephemeralReaderKey: readerPublicKey,
        sessionTranscript,
        algorithm: MacAlgorithm.HS256,
      })
    ).rejects.toThrow(DeviceMacNotSupportedError)
  })

  test('DeviceSignedBuilder.tag only creates a device MAC with HMAC 256/256', async () => {
    const { readerPublicKey } = await createReaderEphemeralKey()

    await expect(
      new DeviceSignedBuilder(mdlDocType, mdocContext).tag({
        deviceKey,
        ephemeralReaderKey: readerPublicKey,
        sessionTranscript,
        algorithm: MacAlgorithm.HS384,
      })
    ).rejects.toThrow(UnsupportedDeviceMacAlgorithmError)
  })

  test('DeviceSignedBuilder.tag creates a device MAC that verifies', async () => {
    const { readerPrivateKey, readerPublicKey } = await createReaderEphemeralKey()
    const issuerSigned = await createIssuerSigned()

    const deviceSigned = await new DeviceSignedBuilder(mdlDocType, mdocContext).tag({
      deviceKey,
      ephemeralReaderKey: readerPublicKey,
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

/**
 * A context that keeps the private keys to itself, as a key management system does, so the keys
 * passed to the library only have a `keyId` and the public key.
 */
function createKmsContext(privateKeys: Array<CoseKey>): MdocContext {
  return {
    ...mdocContext,
    crypto: {
      ...mdocContext.crypto,
      deviceMac: async ({ key, peerPublicKey, salt, info, toBeAuthenticated }) => {
        const kmsKey = privateKeys.find(({ keyId }) => keyId === key.keyId)
        if (!kmsKey) throw new Error(`Unknown key '${key.keyId}'`)

        const sharedSecret = p256.getSharedSecret(kmsKey.d as Uint8Array, peerPublicKey.publicKey, true).slice(1)
        return hmac(sha256, await hkdf('sha256', sharedSecret, salt, info, 32), toBeAuthenticated)
      },
    },
  }
}

function p256Key(key: { x: string; y: string; d?: string }, keyId?: string) {
  return CoseKey.create({
    keyType: KeyType.Ec,
    curve: Curve['P-256'],
    x: hex.decode(key.x),
    y: hex.decode(key.y),
    d: key.d ? hex.decode(key.d) : undefined,
    keyId,
  })
}

// ISO/IEC 18013-5 D.5.1 (session transcript, ephemeral reader key) and D.5.3 (static device key, DeviceAuth).
const annexD = {
  sessionTranscript: SessionTranscript.decode(
    hex.decode(
      'd81859024183d8185858a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa8258c391020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167656d656e746d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6758cd91022548721591020263720102110204616301013000110206616301036e6663005102046163010157001a201e016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d4823a1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f766e642e7766612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298cfccbc35e700a6b020414'
    )
  ),
  readerKey: {
    x: '60e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e',
    y: 'e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa',
    d: 'de3b4b9e5f72dd9b58406ae3091434da48a6f9fd010d88fcb0958e2cebec947c',
  },
  deviceKey: {
    x: '96313d6c63e24e3372742bfdb1a33ba2c897dcd68ab8c753e4fbd48dca6b7f9a',
    y: '1fb3269edd418857de1b39a4e4a44b92fa484caa722c228288f01d0c03a2c3d6',
    d: '6ed542ad4783f0b18c833fadf2171273a35d969c581691ef704359cc7cf1e8c0',
  },
  deviceAuth:
    'a1696465766963654d61638443a10105a0f65820e99521a85ad7891b806a07f8b5388a332d92c189a7bf293ee1f543405ae6824d',
  tag: 'e99521a85ad7891b806a07f8b5388a332d92c189a7bf293ee1f543405ae6824d',
}

describe('device MAC with the ISO/IEC 18013-5 D.5.3 example', () => {
  const { x, y } = annexD.deviceKey
  const deviceKmsContext = createKmsContext([p256Key(annexD.deviceKey, 'device-key')])
  const readerKmsContext = createKmsContext([p256Key(annexD.readerKey, 'reader-key')])

  const tag = (deviceKey: CoseKey, ctx: MdocContext) =>
    new DeviceSignedBuilder(mdlDocType, ctx).tag({
      deviceKey,
      ephemeralReaderKey: p256Key({ x: annexD.readerKey.x, y: annexD.readerKey.y }),
      sessionTranscript: annexD.sessionTranscript,
      algorithm: MacAlgorithm.HS256,
    })

  const deviceAuthenticationBytes = DeviceAuthentication.create({
    sessionTranscript: annexD.sessionTranscript,
    docType: mdlDocType,
    deviceNamespaces: DeviceNamespaces.create({ deviceNamespaces: new Map() }),
  }).encode({ asDataItem: true })

  test('the DeviceAuth is created with the device private key', async () => {
    const deviceSigned = await tag(p256Key(annexD.deviceKey), mdocContext)

    expect(hex.encode(deviceSigned.deviceAuth.encode())).toBe(annexD.deviceAuth)
  })

  test('the tag is created with `crypto.deviceMac` while the device key stays in the key management system', async () => {
    const deviceSigned = await tag(p256Key({ x, y }, 'device-key'), deviceKmsContext)

    expect(hex.encode(deviceSigned.deviceAuth.deviceMac?.tag ?? new Uint8Array())).toBe(annexD.tag)
  })

  test.each([
    ['the reader private key', p256Key(annexD.readerKey), mdocContext],
    [
      '`crypto.deviceMac` while the reader key stays in the key management system',
      p256Key({ x: annexD.readerKey.x, y: annexD.readerKey.y }, 'reader-key'),
      readerKmsContext,
    ],
  ])('the DeviceAuth verifies with %s', async (_, key, ctx) => {
    const deviceMac = DeviceAuth.decode(hex.decode(annexD.deviceAuth)).deviceMac
    const verify = (detachedPayload: Uint8Array) =>
      deviceMac?.verify(
        { key, peerPublicKey: p256Key({ x, y }), sessionTranscript: annexD.sessionTranscript, detachedPayload },
        ctx
      )

    await expect(verify(deviceAuthenticationBytes)).resolves.toBe(true)

    // The DeviceAuthentication of another doc type
    const otherDeviceAuthenticationBytes = DeviceAuthentication.create({
      sessionTranscript: annexD.sessionTranscript,
      docType: 'org.iso.23220.photoid.1',
      deviceNamespaces: DeviceNamespaces.create({ deviceNamespaces: new Map() }),
    }).encode({ asDataItem: true })
    await expect(verify(otherDeviceAuthenticationBytes)).resolves.toBe(false)
  })

  test('the DeviceAuth of an earlier version, which left external_aad out of the MAC_structure, verifies', async () => {
    const { protectedHeaders } = DeviceAuth.decode(hex.decode(annexD.deviceAuth)).deviceMac as DeviceMac
    const legacyTag = await mdocContext.crypto.deviceMac?.({
      key: p256Key(annexD.deviceKey),
      peerPublicKey: p256Key({ x: annexD.readerKey.x, y: annexD.readerKey.y }),
      salt: sha256(annexD.sessionTranscript.encode({ asDataItem: true })),
      info: stringToBytes('EMacKey'),
      toBeAuthenticated: cborEncode(['MAC0', protectedHeaders.encodedStructure, deviceAuthenticationBytes]),
    })
    const legacy = DeviceMac.create({ protectedHeaders, payload: null, tag: legacyTag })

    await expect(
      legacy.verify(
        {
          key: p256Key(annexD.readerKey),
          peerPublicKey: p256Key({ x, y }),
          sessionTranscript: annexD.sessionTranscript,
          detachedPayload: deviceAuthenticationBytes,
        },
        mdocContext
      )
    ).resolves.toBe(true)
  })
})

describe('device MAC with `crypto.deviceMac`', async () => {
  const sessionTranscript = await SessionTranscript.forIsoMdocDcApi(
    { encryptionInfoBase64Url: 'abc', origin: 'https://verifier.example.com' },
    mdocContext
  )

  test('a response is created and verified while the device and reader keys stay in the key management system', async () => {
    const { readerPrivateKey, readerPublicKey } = await createReaderEphemeralKey()
    const ctx = createKmsContext([
      CoseKey.fromJwk({ ...DEVICE_JWK_PRIVATE, kid: 'device-key' }),
      CoseKey.fromJwk({ ...readerPrivateKey.jwk, kid: 'reader-key' }),
    ])

    const deviceResponse = await DeviceResponse.createWithDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          {
            issuerSigned: await createIssuerSigned(),
            docRequestIndex: 0,
            mac: {
              deviceKey: CoseKey.fromJwk({ ...DEVICE_JWK_PUBLIC, kid: 'device-key' }),
              ephemeralReaderKey: readerPublicKey,
            },
          },
        ],
      },
      ctx
    )

    await expect(
      deviceResponse.verify(
        {
          sessionTranscript,
          ephemeralReaderKey: CoseKey.fromJwk({ ...readerPublicKey.jwk, kid: 'reader-key' }),
          trustedCertificates,
        },
        ctx
      )
    ).resolves.toBeDefined()

    // The tag is the same as with the private keys in the context
    await expect(
      deviceResponse.verify(
        { sessionTranscript, ephemeralReaderKey: readerPrivateKey, trustedCertificates },
        mdocContext
      )
    ).resolves.toBeDefined()
  })

  test('a device MAC for another reader key FAILS', async () => {
    const { readerPublicKey } = await createReaderEphemeralKey()
    const other = await createReaderEphemeralKey()
    const ctx = createKmsContext([CoseKey.fromJwk({ ...other.readerPrivateKey.jwk, kid: 'reader-key' })])
    const deviceResponse = await createMacResponse(sessionTranscript, readerPublicKey)

    await expect(
      deviceResponse.verify(
        {
          sessionTranscript,
          ephemeralReaderKey: CoseKey.fromJwk({ ...other.readerPublicKey.jwk, kid: 'reader-key' }),
          trustedCertificates,
        },
        ctx
      )
    ).rejects.toThrow('Device MAC must be valid')
  })
})
