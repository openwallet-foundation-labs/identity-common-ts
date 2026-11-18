import 'reflect-metadata'
import { MacAlgorithm } from '@owf/cose'
import { expect, suite, test } from 'vitest'
import {
  CoseKey,
  DeviceRequest,
  DeviceResponse,
  DeviceSignedBuilder,
  DocRequest,
  ItemsRequest,
  type ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  SessionTranscript,
  SignatureAlgorithm,
  type UnprotectedHeaders,
} from '../..'
import { DEVICE_JWK_PRIVATE } from '../config'
import { mdocContext } from '../context'
import {
  createIssuerSigned,
  issuerCertificate,
  mdlDocType,
  mdlNamespace,
  RECIPIENT_JWK_PRIVATE,
  RECIPIENT_JWK_PUBLIC,
} from '../iso-mdoc-dc-api/fixtures'

// A key id that only the signer knows, such as the id of the key in a key management system
const deviceKey = CoseKey.fromJwk({ ...DEVICE_JWK_PRIVATE, kid: 'kms-key-id' })
const readerKey = CoseKey.fromJwk(RECIPIENT_JWK_PUBLIC)
const trustedCertificates = [{ issuance: [issuerCertificate] }]

const deviceRequest = DeviceRequest.create({
  docRequests: [
    DocRequest.create({
      itemsRequest: ItemsRequest.create({ docType: mdlDocType, namespaces: { [mdlNamespace]: { family_name: true } } }),
    }),
  ],
})

const hasKid = (structure?: { protectedHeaders: ProtectedHeaders; unprotectedHeaders: UnprotectedHeaders }) =>
  structure?.protectedHeaders.headers?.has(RegisteredCwtHeaderClaimKey.KeyId) ||
  structure?.unprotectedHeaders.headers?.has(RegisteredCwtHeaderClaimKey.KeyId)

// ISO/IEC 18013-5 identifies the issuer key by the x5chain and the device key by the MSO, so the keyId
// of a signing key is not written as a kid header.
suite('kid header', async () => {
  const sessionTranscript = await SessionTranscript.forIsoMdocDcApi(
    { encryptionInfoBase64Url: 'abc', origin: 'https://verifier.example.com' },
    mdocContext
  )

  test('IssuerAuth and DeviceSignature have no kid when the keys have a keyId', async () => {
    // `createIssuerSigned` signs with an issuer key with keyId '1234'
    const deviceResponse = DeviceResponse.decode(
      (
        await DeviceResponse.createWithDeviceRequest(
          {
            deviceRequest,
            sessionTranscript,
            documents: [
              { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
            ],
          },
          mdocContext
        )
      ).encode()
    )

    const document = deviceResponse.documents?.[0]
    expect(hasKid(document?.issuerSigned.issuerAuth)).toBe(false)
    expect(hasKid(document?.deviceSigned.deviceAuth.deviceSignature)).toBe(false)
    await expect(deviceResponse.verify({ sessionTranscript, trustedCertificates }, mdocContext)).resolves.toBeDefined()
  })

  test('DeviceMac has no kid when the device key has a keyId', async () => {
    const deviceResponse = DeviceResponse.decode(
      (
        await DeviceResponse.createWithDeviceRequest(
          {
            deviceRequest,
            sessionTranscript,
            documents: [
              {
                issuerSigned: await createIssuerSigned(),
                docRequestIndex: 0,
                mac: { deviceKey, ephemeralReaderKey: readerKey },
              },
            ],
          },
          mdocContext
        )
      ).encode()
    )

    expect(hasKid(deviceResponse.documents?.[0].deviceSigned.deviceAuth.deviceMac)).toBe(false)
    await expect(
      deviceResponse.verify(
        { sessionTranscript, ephemeralReaderKey: CoseKey.fromJwk(RECIPIENT_JWK_PRIVATE), trustedCertificates },
        mdocContext
      )
    ).resolves.toBeDefined()
  })

  test('DeviceSignedBuilder.sign and DeviceSignedBuilder.tag write no kid when the device key has a keyId', async () => {
    const signed = await new DeviceSignedBuilder(mdlDocType, mdocContext).sign({
      signingKey: deviceKey,
      algorithm: SignatureAlgorithm.ES256,
      sessionTranscript,
    })
    const tagged = await new DeviceSignedBuilder(mdlDocType, mdocContext).tag({
      deviceKey,
      ephemeralReaderKey: readerKey,
      sessionTranscript,
      algorithm: MacAlgorithm.HS256,
    })

    expect(hasKid(signed.deviceAuth.deviceSignature)).toBe(false)
    expect(hasKid(tagged.deviceAuth.deviceMac)).toBe(false)
  })
})
