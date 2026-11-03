import 'reflect-metadata'
import { X509Certificate } from '@peculiar/x509'
import { expect, suite, test, vi } from 'vitest'
import {
  CoseKey,
  DeviceAuth,
  DeviceKey,
  DeviceRequest,
  DeviceResponse,
  DeviceSignature,
  DocRequest,
  Holder,
  Issuer,
  IssuerSigned,
  ItemsRequest,
  RegisteredCwtHeaderClaimKey,
  SessionTranscript,
  SignatureAlgorithm,
  Verifier,
} from '../..'
import { DEVICE_JWK_PRIVATE, DEVICE_JWK_PUBLIC, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK } from '../config'
import { mdocContext } from '../context'

const signed = new Date('2023-10-24T14:55:18Z')
const validFrom = new Date(signed)
validFrom.setMinutes(signed.getMinutes() + 5)
const validUntil = new Date(signed)
validUntil.setFullYear(signed.getFullYear() + 30)

const trustedCertificates = [
  {
    issuance: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
    status: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
  },
]

/** The P-256 device key, with the `alg` the device signature is created with. */
const deviceSigningKey = (algorithm: SignatureAlgorithm) => {
  const { keyType, curve, x, y, d } = CoseKey.fromJwk(DEVICE_JWK_PRIVATE)
  return CoseKey.create({ keyType, curve, x, y, d, algorithm })
}

/** Issue an mdoc and present it with a device signature of `algorithm`. */
async function presentMdoc(algorithm: SignatureAlgorithm) {
  const issuer = new Issuer('org.iso.18013.5.1', mdocContext)
  issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', { first_name: 'First' })

  const issuerSigned = await issuer.sign({
    signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
    certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
    validityInfo: { signed, validFrom, validUntil },
  })

  const deviceRequest = DeviceRequest.create({
    docRequests: [
      DocRequest.create({
        itemsRequest: ItemsRequest.create({
          docType: 'org.iso.18013.5.1',
          namespaces: { 'org.iso.18013.5.1.mDL': { first_name: true } },
        }),
      }),
    ],
  })

  const sessionTranscript = await SessionTranscript.forOid4Vp(
    { clientId: 'my-client-id', responseUri: 'my-response-uri.com', nonce: 'my-random-nonce' },
    mdocContext
  )

  const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
    {
      deviceRequest,
      sessionTranscript,
      documents: [
        {
          issuerSigned: IssuerSigned.fromEncodedForOid4Vci(issuerSigned.encodedForOid4Vci),
          docRequestIndex: 0,
          signature: { signingKey: deviceSigningKey(algorithm) },
        },
      ],
    },
    mdocContext
  )

  return {
    deviceResponse: DeviceResponse.fromEncodedForOid4Vp(deviceResponse.encodedForOid4Vp),
    deviceRequest,
    sessionTranscript,
  }
}

suite('device signature algorithm', () => {
  // RFC 9864 § 2.1: ESP256 is ECDSA with P-256 and SHA-256.
  test('a device signature with ESP256 verifies end to end', async () => {
    const { deviceResponse, deviceRequest, sessionTranscript } = await presentMdoc(SignatureAlgorithm.ESP256)

    const deviceSignature = deviceResponse.documents?.[0].deviceSigned.deviceAuth.deviceSignature
    expect(deviceSignature?.algorithm).toBe(SignatureAlgorithm.ESP256)

    await expect(
      Verifier.verifyDeviceResponse(
        { deviceRequest, deviceResponse, sessionTranscript, trustedCertificates },
        mdocContext
      )
    ).resolves.toBeDefined()
  })

  test('a device signature whose alg requires another curve than the device key fails', async () => {
    const { deviceResponse, sessionTranscript } = await presentMdoc(SignatureAlgorithm.ES256)
    const document = deviceResponse.documents?.[0]
    const deviceSignature = document?.deviceSigned.deviceAuth.deviceSignature
    if (!document || !deviceSignature) throw new Error('The device response has no device signature')

    // The same signature, with an alg that requires a P-384 key while the device key is on P-256.
    const deviceAuth = DeviceAuth.create({
      deviceSignature: DeviceSignature.create({
        protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ESP384]]),
        unprotectedHeaders: deviceSignature.unprotectedHeaders,
        payload: null,
        signature: deviceSignature.signature,
      }),
    })
    const verify = vi.fn(mdocContext.cose.sign1.verify)
    const verificationCallback = vi.fn()

    await deviceAuth.verify(
      { document, sessionTranscript, verificationCallback },
      { ...mdocContext, cose: { ...mdocContext.cose, sign1: { ...mdocContext.cose.sign1, verify } } }
    )

    expect(verificationCallback).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 'FAILED',
        check: 'Device signature must be valid',
        reason: expect.stringContaining('Algorithm ESP384 requires an EC2 key on curve P-384'),
      })
    )
    expect(verify).not.toHaveBeenCalled()
  })
})
