import { cborEncode } from '@owf/cose'
import { base64url, hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import {
  AgeOverLimitExceededError,
  CoseKey,
  DeviceRequest,
  DocRequest,
  EncryptedResponse,
  EncryptedResponseData,
  EncryptionInfo,
  EncryptionParameters,
  InvalidDcApiRequestError,
  InvalidDcApiResponseError,
  InvalidEncryptionInfoError,
  InvalidOriginError,
  IsoMdocDcApi,
  ItemsRequest,
  MissingOriginError,
  RegisteredCwtHeaderClaimKey,
  type VerificationAssessment,
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
} from './fixtures'
import { createReaderCertificate } from './reader-certificate'

const origin = 'https://verifier.example.com'
const deviceKey = CoseKey.fromJwk(DEVICE_JWK_PRIVATE)
const recipientPublicKey = CoseKey.fromJwk(RECIPIENT_JWK_PUBLIC)
const recipientPrivateKey = CoseKey.fromJwk(RECIPIENT_JWK_PRIVATE)
const trustedCertificates = [{ issuance: [issuerCertificate] }]

const requestedNamespaces = {
  [mdlNamespace]: { family_name: true, given_name: false },
}

async function createRequest() {
  return await IsoMdocDcApi.createRequest(
    {
      docRequests: [{ docType: mdlDocType, namespaces: requestedNamespaces }],
      recipientPublicKey,
    },
    mdocContext
  )
}

describe('IsoMdocDcApi round trip', () => {
  test('request → response → decrypt → verify', async () => {
    const issuerSigned = await createIssuerSigned()

    const { request } = await createRequest()

    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    expect(parsedRequest.docRequests).toHaveLength(1)
    expect(parsedRequest.docRequests[0].docType).toBe(mdlDocType)
    expect(parsedRequest.docRequests[0].hasReaderAuth).toBe(false)
    expect(parsedRequest.encryptionInfo.nonce).toHaveLength(16)

    const response = await IsoMdocDcApi.createResponse(
      { parsedRequest, documents: [{ issuerSigned, deviceKey, docRequestIndex: 0 }] },
      mdocContext
    )

    const { deviceResponse, verificationResult } = await IsoMdocDcApi.verifyResponse(
      {
        response,
        origin,
        encryptionInfo: request.encryptionInfo,
        recipientKey: recipientPrivateKey,
        deviceRequest: DeviceRequest.decode(base64url.decode(request.deviceRequest)),
        trustedCertificates,
      },
      mdocContext
    )

    expect(verificationResult.documents).toHaveLength(1)
    expect(verificationResult.deviceRequestMatch?.success).toBe(true)
    expect(deviceResponse.documents?.[0].docType).toBe(mdlDocType)

    // Only the requested elements are disclosed.
    const claims = deviceResponse.documents?.[0].issuerSigned.getPrettyClaims(mdlNamespace)
    expect(claims).toStrictEqual({ family_name: 'Doe', given_name: 'John' })
  })

  test('encrypted response carries a raw 65-byte P-256 enc, not a COSE_Key', async () => {
    const issuerSigned = await createIssuerSigned()
    const { request } = await createRequest()

    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    const { response } = await IsoMdocDcApi.createResponse(
      { parsedRequest, documents: [{ issuerSigned, deviceKey, docRequestIndex: 0 }] },
      mdocContext
    )

    const encryptedResponse = EncryptedResponse.fromBase64Url(response)
    expect(encryptedResponse.enc).toHaveLength(65)
    expect(encryptedResponse.enc[0]).toBe(0x04)
  })

  test('a response relayed to a different origin cannot be decrypted', async () => {
    const issuerSigned = await createIssuerSigned()
    const { request } = await createRequest()

    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    const response = await IsoMdocDcApi.createResponse(
      { parsedRequest, documents: [{ issuerSigned, deviceKey, docRequestIndex: 0 }] },
      mdocContext
    )

    await expect(
      IsoMdocDcApi.decryptResponse(
        {
          response,
          origin: 'https://attacker.example.com',
          encryptionInfo: request.encryptionInfo,
          recipientKey: recipientPrivateKey,
        },
        mdocContext
      )
    ).rejects.toThrow()
  })

  test('parseRequest aborts when the DC API provided no origin (C.5)', async () => {
    const { request } = await createRequest()

    await expect(IsoMdocDcApi.parseRequest({ request, origin: undefined }, mdocContext)).rejects.toThrow(
      MissingOriginError
    )
  })

  test('createRequest refuses to request more than two age_over_NN elements in a namespace', async () => {
    await expect(
      IsoMdocDcApi.createRequest(
        {
          docRequests: [
            {
              docType: mdlDocType,
              namespaces: { [mdlNamespace]: { age_over_18: false, age_over_21: false, age_over_65: false } },
            },
          ],
          recipientPublicKey,
        },
        mdocContext
      )
    ).rejects.toThrow(
      new AgeOverLimitExceededError(
        `Items request for docType '${mdlDocType}' requests 'age_over_18', 'age_over_21', 'age_over_65' in namespace '${mdlNamespace}', but at most two age_over_NN elements may be requested per namespace`
      )
    )
  })

  test('parseRequest rejects a request for more than two age_over_NN elements in a namespace', async () => {
    const { request } = await createRequest()

    // `ItemsRequest.create` refuses such a request, so it is built from its structure.
    const deviceRequest = DeviceRequest.create({
      docRequests: [
        DocRequest.create({
          itemsRequest: ItemsRequest.fromEncodedStructure(
            new Map<unknown, unknown>([
              ['docType', mdlDocType],
              [
                'nameSpaces',
                new Map([
                  [
                    mdlNamespace,
                    new Map([
                      ['age_over_18', false],
                      ['age_over_21', false],
                      ['age_over_65', false],
                    ]),
                  ],
                ]),
              ],
            ])
          ),
        }),
      ],
    })

    await expect(
      IsoMdocDcApi.parseRequest(
        { request: { ...request, deviceRequest: base64url.encode(deviceRequest.encode()) }, origin },
        mdocContext
      )
    ).rejects.toThrow(
      `Doc request 0 requests 'age_over_18', 'age_over_21', 'age_over_65' in namespace '${mdlNamespace}'`
    )
  })

  test('parseRequest rejects a nonce with less than 16 bytes', async () => {
    const { request } = await createRequest()

    const shortNonce = EncryptionInfo.create({
      encryptionParameters: EncryptionParameters.create({
        nonce: hex.decode('00112233445566778899aabb'),
        recipientPublicKey,
      }),
    })

    await expect(
      IsoMdocDcApi.parseRequest(
        { request: { ...request, encryptionInfo: shortNonce.toBase64Url() }, origin },
        mdocContext
      )
    ).rejects.toThrow(InvalidEncryptionInfoError)
  })

  test('createRequest rejects a nonce with less than 16 bytes', async () => {
    await expect(
      IsoMdocDcApi.createRequest(
        {
          docRequests: [{ docType: mdlDocType, namespaces: requestedNamespaces }],
          recipientPublicKey,
          nonce: hex.decode('00112233445566778899aabb'),
        },
        mdocContext
      )
    ).rejects.toThrow(InvalidEncryptionInfoError)
  })

  test('createRequest rejects a recipient key that is not P-256', async () => {
    await expect(
      IsoMdocDcApi.createRequest(
        {
          docRequests: [{ docType: mdlDocType, namespaces: requestedNamespaces }],
          recipientPublicKey: CoseKey.fromJwk({
            kty: 'OKP',
            crv: 'Ed25519',
            x: 'gCTHOgU_uZLdSTHo-BvNBGXO83SwCajwZAaJT1lhbjw',
          }),
        },
        mdocContext
      )
    ).rejects.toThrow(InvalidEncryptionInfoError)
  })

  test('verification fails when the ciphertext is tampered with', async () => {
    const issuerSigned = await createIssuerSigned()
    const { request } = await createRequest()

    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    const { response } = await IsoMdocDcApi.createResponse(
      { parsedRequest, documents: [{ issuerSigned, deviceKey, docRequestIndex: 0 }] },
      mdocContext
    )

    const encryptedResponse = EncryptedResponse.fromBase64Url(response)
    const ciphertext = new Uint8Array(encryptedResponse.ciphertext)
    ciphertext[0] ^= 0xff

    const tampered = EncryptedResponse.create({
      encryptedResponseData: EncryptedResponseData.create({ enc: encryptedResponse.enc, ciphertext }),
    })

    await expect(
      IsoMdocDcApi.decryptResponse(
        {
          response: tampered.toBase64Url(),
          origin,
          encryptionInfo: request.encryptionInfo,
          recipientKey: recipientPrivateKey,
        },
        mdocContext
      )
    ).rejects.toThrow()
  })

  test('createResponse answers a multi-document request', async () => {
    const mdl = await createIssuerSigned()
    const photoIdDocType = 'org.iso.23220.photoid.1'
    const photoId = await createIssuerSigned({ docType: photoIdDocType })

    const { request } = await IsoMdocDcApi.createRequest(
      {
        docRequests: [
          { docType: mdlDocType, namespaces: requestedNamespaces },
          { docType: photoIdDocType, namespaces: requestedNamespaces },
        ],
        recipientPublicKey,
      },
      mdocContext
    )

    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    const response = await IsoMdocDcApi.createResponse(
      {
        parsedRequest,
        documents: [
          { issuerSigned: mdl, deviceKey, docRequestIndex: 0 },
          { issuerSigned: photoId, deviceKey, docRequestIndex: 1 },
        ],
      },
      mdocContext
    )

    const { deviceResponse } = await IsoMdocDcApi.decryptResponse(
      { response, origin, encryptionInfo: request.encryptionInfo, recipientKey: recipientPrivateKey },
      mdocContext
    )

    expect(deviceResponse.documents?.map((d) => d.docType)).toStrictEqual([mdlDocType, photoIdDocType])
  })

  test('createResponse may answer only part of a request', async () => {
    const mdl = await createIssuerSigned()
    const photoIdDocType = 'org.iso.23220.photoid.1'

    const { request } = await IsoMdocDcApi.createRequest(
      {
        docRequests: [
          { docType: mdlDocType, namespaces: requestedNamespaces },
          { docType: photoIdDocType, namespaces: requestedNamespaces },
        ],
        recipientPublicKey,
      },
      mdocContext
    )

    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    const response = await IsoMdocDcApi.createResponse(
      { parsedRequest, documents: [{ issuerSigned: mdl, deviceKey, docRequestIndex: 0 }] },
      mdocContext
    )

    const { deviceResponse } = await IsoMdocDcApi.decryptResponse(
      { response, origin, encryptionInfo: request.encryptionInfo, recipientKey: recipientPrivateKey },
      mdocContext
    )

    expect(deviceResponse.documents).toHaveLength(1)
  })

  test('createResponse throws when the context has no HPKE support', async () => {
    const issuerSigned = await createIssuerSigned()
    const { request } = await createRequest()
    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)

    const contextWithoutHpke = { ...mdocContext, crypto: { ...mdocContext.crypto, hpke: undefined } }

    await expect(
      IsoMdocDcApi.createResponse(
        { parsedRequest, documents: [{ issuerSigned, deviceKey, docRequestIndex: 0 }] },
        contextWithoutHpke
      )
    ).rejects.toThrow('does not provide HPKE support')
  })
})

describe('IsoMdocDcApi reader auth', () => {
  test('a signed request is verified against the transcript of its origin', async () => {
    const { readerKey, readerCertificate } = await createReaderCertificate()

    const { request } = await IsoMdocDcApi.createRequest(
      {
        docRequests: [{ docType: mdlDocType, namespaces: requestedNamespaces }],
        recipientPublicKey,
        readerAuth: { signingKey: readerKey, certificateChain: [readerCertificate], origin },
      },
      mdocContext
    )

    const checks: Array<VerificationAssessment> = []
    const parsedRequest = await IsoMdocDcApi.parseRequest(
      {
        request,
        origin,
        trustedReaderCertificates: [readerCertificate],
        verificationCallback: (assessment) => checks.push(assessment),
      },
      mdocContext
    )

    expect(parsedRequest.docRequests[0].hasReaderAuth).toBe(true)
    expect(parsedRequest.docRequests[0].readerCertificateChain).toHaveLength(1)
    expect(checks.filter((check) => check.status === 'FAILED')).toStrictEqual([])
  })

  test('a signed request fails verification at a different origin', async () => {
    const { readerKey, readerCertificate } = await createReaderCertificate()

    const { request } = await IsoMdocDcApi.createRequest(
      {
        docRequests: [{ docType: mdlDocType, namespaces: requestedNamespaces }],
        recipientPublicKey,
        readerAuth: { signingKey: readerKey, certificateChain: [readerCertificate], origin },
      },
      mdocContext
    )

    const checks: Array<VerificationAssessment> = []
    await IsoMdocDcApi.parseRequest(
      {
        request,
        origin: 'https://other.example.com',
        verificationCallback: (assessment) => checks.push(assessment),
      },
      mdocContext
    )

    const signatureCheck = checks.find((check) => check.check === 'Reader auth signature must be valid')
    expect(signatureCheck?.status).toBe('FAILED')
  })

  test('a signed request without trusted reader certificates fails, unless chain validation is disabled', async () => {
    const { readerKey, readerCertificate } = await createReaderCertificate()

    const { request } = await IsoMdocDcApi.createRequest(
      {
        docRequests: [{ docType: mdlDocType, namespaces: requestedNamespaces }],
        recipientPublicKey,
        readerAuth: { signingKey: readerKey, certificateChain: [readerCertificate], origin },
      },
      mdocContext
    )

    await expect(IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)).rejects.toThrow(
      'No trusted reader certificates provided.'
    )

    const parsedRequest = await IsoMdocDcApi.parseRequest(
      { request, origin, disableReaderCertificateChainValidation: true },
      mdocContext
    )
    expect(parsedRequest.docRequests[0].hasReaderAuth).toBe(true)
  })
})

describe('IsoMdocDcApi payload validation', () => {
  test.each([
    ['a missing member', { deviceRequest: 'aGVsbG8' }],
    ['a member that is not a string', { deviceRequest: 'aGVsbG8', encryptionInfo: 42 }],
    ['a member that is not base64url', { deviceRequest: 'aGVsbG8', encryptionInfo: 'not base64url!' }],
    ['a padded member', { deviceRequest: 'aGVsbG8', encryptionInfo: 'aGVsbG8=' }],
    ['a payload that is not an object', 'not-an-object'],
  ])('parseRequest rejects a request with %s', async (_, request) => {
    await expect(IsoMdocDcApi.parseRequest({ request: request as any, origin }, mdocContext)).rejects.toThrow(
      InvalidDcApiRequestError
    )
  })

  test('decryptResponse rejects a malformed response', async () => {
    const { request } = await createRequest()

    await expect(
      IsoMdocDcApi.decryptResponse(
        {
          response: { response: 'not base64url!' } as any,
          origin,
          encryptionInfo: request.encryptionInfo,
          recipientKey: recipientPrivateKey,
        },
        mdocContext
      )
    ).rejects.toThrow(InvalidDcApiResponseError)
  })

  test('decryptResponse accepts the response as a bare string', async () => {
    const issuerSigned = await createIssuerSigned()
    const { request } = await createRequest()
    const parsedRequest = await IsoMdocDcApi.parseRequest({ request, origin }, mdocContext)
    const { response } = await IsoMdocDcApi.createResponse(
      { parsedRequest, documents: [{ issuerSigned, deviceKey, docRequestIndex: 0 }] },
      mdocContext
    )

    const { deviceResponse } = await IsoMdocDcApi.decryptResponse(
      { response, origin, encryptionInfo: request.encryptionInfo, recipientKey: recipientPrivateKey },
      mdocContext
    )

    expect(deviceResponse.documents).toHaveLength(1)
  })
})

describe('IsoMdocDcApi input handling', () => {
  test.each([
    ['a trailing slash', 'https://verifier.example.com/'],
    ['a path', 'https://verifier.example.com/path'],
    ['a default port', 'https://verifier.example.com:443'],
    ['an upper case host', 'https://Verifier.example.com'],
    ['an opaque origin', 'null'],
    ['no scheme', 'verifier.example.com'],
  ])('parseRequest rejects an origin with %s', async (_, invalidOrigin) => {
    const { request } = await createRequest()

    await expect(IsoMdocDcApi.parseRequest({ request, origin: invalidOrigin }, mdocContext)).rejects.toThrow(
      InvalidOriginError
    )
  })

  test('createRequest and decryptResponse reject an origin that is not serialized', async () => {
    const { readerKey, readerCertificate } = await createReaderCertificate()
    const { request } = await createRequest()

    await expect(
      IsoMdocDcApi.createRequest(
        {
          docRequests: [{ docType: mdlDocType, namespaces: requestedNamespaces }],
          recipientPublicKey,
          readerAuth: { signingKey: readerKey, certificateChain: [readerCertificate], origin: `${origin}/` },
        },
        mdocContext
      )
    ).rejects.toThrow(InvalidOriginError)

    await expect(
      IsoMdocDcApi.decryptResponse(
        {
          response: 'aGVsbG8',
          origin: `${origin}/`,
          encryptionInfo: request.encryptionInfo,
          recipientKey: recipientPrivateKey,
        },
        mdocContext
      )
    ).rejects.toThrow(InvalidOriginError)
  })

  test.each([
    ['encryption info that is not CBOR', { encryptionInfo: base64url.encode(Uint8Array.of(0xff)) }],
    ['encryption info of another structure', { encryptionInfo: base64url.encode(cborEncode(['dcapi', 1])) }],
    ['a device request that is not CBOR', { deviceRequest: base64url.encode(Uint8Array.of(0xff)) }],
    ['a device request of another structure', { deviceRequest: base64url.encode(cborEncode(new Map())) }],
  ])('parseRequest rejects %s', async (_, override) => {
    const { request } = await createRequest()

    await expect(
      IsoMdocDcApi.parseRequest({ request: { ...request, ...override }, origin }, mdocContext)
    ).rejects.toThrow(InvalidDcApiRequestError)
  })

  test('decryptResponse rejects an encrypted response of another structure', async () => {
    const { request } = await createRequest()

    await expect(
      IsoMdocDcApi.decryptResponse(
        {
          response: base64url.encode(cborEncode(['dcapi', 'not a map'])),
          origin,
          encryptionInfo: request.encryptionInfo,
          recipientKey: recipientPrivateKey,
        },
        mdocContext
      )
    ).rejects.toThrow(InvalidDcApiResponseError)
  })

  test('reader auth without a certificate FAILS through the verification callback', async () => {
    const { readerKey, readerCertificate } = await createReaderCertificate()
    const { request, deviceRequest } = await IsoMdocDcApi.createRequest(
      {
        docRequests: [{ docType: mdlDocType, namespaces: requestedNamespaces }],
        recipientPublicKey,
        readerAuth: { signingKey: readerKey, certificateChain: [readerCertificate], origin },
      },
      mdocContext
    )

    const [docRequest] = deviceRequest.docRequests
    docRequest.readerAuth?.unprotectedHeaders.headers?.delete(RegisteredCwtHeaderClaimKey.X5Chain)
    const withoutCertificate = base64url.encode(deviceRequest.encode())

    const checks: Array<VerificationAssessment> = []
    await IsoMdocDcApi.parseRequest(
      {
        request: { ...request, deviceRequest: withoutCertificate },
        origin,
        disableReaderCertificateChainValidation: true,
        verificationCallback: (check) => checks.push(check),
      },
      mdocContext
    )

    const signatureCheck = checks.find((check) => check.check === 'Reader auth signature must be valid')
    expect(signatureCheck?.status).toBe('FAILED')
    expect(signatureCheck?.reason).toContain('Unable to verify the reader auth signature')
  })
})
