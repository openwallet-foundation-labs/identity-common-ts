import 'reflect-metadata'
import { hex } from '@owf/identity-common'
import { AuthorityKeyIdentifierExtension, SubjectKeyIdentifierExtension, X509Certificate } from '@peculiar/x509'
import { assert, describe, expect, test } from 'vitest'
import { z } from 'zod'
import {
  CoseKey,
  DeviceRequest,
  DeviceRequestInfo,
  DocRequest,
  DocRequestInfo,
  Holder,
  InvalidElementSelectionError,
  ItemsRequest,
  MissingRequestedElementError,
  SessionTranscript,
  UnsatisfiedDeviceRequestError,
  type VerificationAssessment,
  Verifier,
} from '../..'
import { Handover } from '../../mdoc/models/handover'
import { certificateKeyIdentifiers } from '../../utils/keyIdentifiers'
import { DEVICE_JWK_PRIVATE, ISSUER_CERTIFICATE } from '../config'
import { mdocContext } from '../context'
import { createIssuerSigned, issuerCertificate, mdlDocType, mdlNamespace } from '../iso-mdoc-dc-api/fixtures'

/**
 * The request information of ISO/IEC TS 23220-4 7.2.1: alternative data elements, issuer
 * identifiers and use cases, matched on the holder side and on the verifier side.
 */

class NullHandover extends Handover<null> {
  static get encodingSchema() {
    return z.null()
  }
}

const deviceKey = CoseKey.fromJwk(DEVICE_JWK_PRIVATE)
const sessionTranscript = SessionTranscript.create({ handover: NullHandover.fromEncodedStructure(null) })
const photoIdDocType = 'org.iso.23220.photoid.1'

const issuerKeyIdentifier = hex.decode(
  new X509Certificate(ISSUER_CERTIFICATE).getExtension(SubjectKeyIdentifierExtension)?.keyId ?? ''
)

const createDeviceRequest = (options: {
  docRequests: Array<{
    docType?: string
    namespaces: Record<string, Record<string, boolean>>
    requestInfo?: DocRequestInfo
  }>
  useCases?: Array<{ mandatory: boolean; documentSets: Array<Array<number>> }>
}) =>
  DeviceRequest.create({
    docRequests: options.docRequests.map(({ docType, namespaces, requestInfo }) =>
      DocRequest.create({
        itemsRequest: ItemsRequest.create({ docType: docType ?? mdlDocType, namespaces, requestInfo }),
      })
    ),
    deviceRequestInfo: options.useCases ? DeviceRequestInfo.create({ useCases: options.useCases }) : undefined,
  })

const ageInYearsOrAgeOver18 = DocRequestInfo.create({
  alternativeDataElements: [
    {
      requestedElement: [mdlNamespace, 'age_in_years'],
      alternativeElementSets: [[[mdlNamespace, 'age_birth_year']], [[mdlNamespace, 'age_over_18']]],
    },
  ],
})

describe('certificateKeyIdentifiers', () => {
  test('reads the subject and authority key identifiers as @peculiar/x509 does', () => {
    const certificate = new X509Certificate(ISSUER_CERTIFICATE)

    expect(certificateKeyIdentifiers(issuerCertificate).map((id) => hex.encode(id))).toStrictEqual([
      certificate.getExtension(SubjectKeyIdentifierExtension)?.keyId,
      certificate.getExtension(AuthorityKeyIdentifierExtension)?.keyId,
    ])
  })

  test('yields nothing for bytes that are not a certificate', () => {
    expect(certificateKeyIdentifiers(new Uint8Array([0x30, 0x82, 0xff]))).toStrictEqual([])
  })
})

describe('alternative data elements', () => {
  test('a holder answers a missing element with the first alternative set it has', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [{ namespaces: { [mdlNamespace]: { age_in_years: false } }, requestInfo: ageInYearsOrAgeOver18 }],
    })

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [await createIssuerSigned({ claims: { age_over_18: true } })],
    })

    assert(match.success)
    const [claim] = match.docRequests[0].validCredentials[0]?.claims.validClaims ?? []
    expect(claim).toStrictEqual({
      success: true,
      namespace: mdlNamespace,
      elementIdentifier: 'age_in_years',
      intentToRetain: false,
      optional: false,
      disclosedElementIdentifier: 'age_over_18',
      elementValue: true,
      source: 'issuerSigned',
      alternativeElements: [
        { namespace: mdlNamespace, elementIdentifier: 'age_over_18', elementValue: true, source: 'issuerSigned' },
      ],
      options: [
        {
          alternativeElementSetIndex: 1,
          elements: [
            { namespace: mdlNamespace, elementIdentifier: 'age_over_18', elementValue: true, source: 'issuerSigned' },
          ],
        },
      ],
    })
  })

  test('a holder keeps the requested element when it has it', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [{ namespaces: { [mdlNamespace]: { age_in_years: false } }, requestInfo: ageInYearsOrAgeOver18 }],
    })

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [await createIssuerSigned({ claims: { age_in_years: 36, age_over_18: true } })],
    })

    assert(match.success)
    const [claim] = match.docRequests[0].validCredentials[0]?.claims.validClaims ?? []
    expect(claim).toMatchObject({ disclosedElementIdentifier: 'age_in_years', elementValue: 36 })
    expect(claim).not.toHaveProperty('alternativeElements')
  })

  test("a holder is offered every option, the requested element first, then the alternative sets in the reader's order", async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [{ namespaces: { [mdlNamespace]: { age_in_years: false } }, requestInfo: ageInYearsOrAgeOver18 }],
    })

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [
        await createIssuerSigned({ claims: { age_in_years: 36, age_birth_year: 1990, age_over_18: true } }),
      ],
    })

    assert(match.success)
    const [claim] = match.docRequests[0].validCredentials[0]?.claims.validClaims ?? []
    expect(
      claim?.options?.map((option) => [
        option.alternativeElementSetIndex,
        option.elements.map((element) => element.elementIdentifier),
      ])
    ).toStrictEqual([
      [undefined, ['age_in_years']],
      [0, ['age_birth_year']],
      [1, ['age_over_18']],
    ])
  })

  test('a claim without alternatives in the request lists no options', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [{ namespaces: { [mdlNamespace]: { family_name: false } }, requestInfo: ageInYearsOrAgeOver18 }],
    })

    const match = Holder.matchDeviceRequest({ deviceRequest, credentials: [await createIssuerSigned()] })

    assert(match.success)
    expect(match.docRequests[0].validCredentials[0]?.claims.validClaims[0]).not.toHaveProperty('options')
  })

  test('a holder can disclose an alternative set in place of the requested element it has', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [{ namespaces: { [mdlNamespace]: { age_in_years: false } }, requestInfo: ageInYearsOrAgeOver18 }],
    })
    const issuerSigned = await createIssuerSigned({ claims: { age_in_years: 36, age_over_18: true } })

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          {
            issuerSigned,
            docRequestIndex: 0,
            alternatives: { [mdlNamespace]: { age_in_years: 1 } },
            signature: { signingKey: deviceKey },
          },
        ],
      },
      mdocContext
    )

    const disclosed = deviceResponse.documents?.[0].issuerSigned.getIssuerNamespace(mdlNamespace)
    expect(disclosed?.map((item) => item.elementIdentifier)).toStrictEqual(['age_over_18'])
    expect(Verifier.matchDeviceRequest({ deviceRequest, deviceResponse }).success).toBe(true)
  })

  test('a holder cannot pick an alternative set the request does not have, or the credential cannot disclose', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [{ namespaces: { [mdlNamespace]: { age_in_years: false } }, requestInfo: ageInYearsOrAgeOver18 }],
    })
    const issuerSigned = await createIssuerSigned({ claims: { age_in_years: 36 } })
    const create = (alternatives: Record<string, Record<string, number>>) =>
      Holder.createDeviceResponseForDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [{ issuerSigned, docRequestIndex: 0, alternatives, signature: { signingKey: deviceKey } }],
        },
        mdocContext
      )

    await expect(create({ [mdlNamespace]: { age_in_years: 2 } })).rejects.toThrow(InvalidElementSelectionError)
    await expect(create({ [mdlNamespace]: { family_name: 0 } })).rejects.toThrow(InvalidElementSelectionError)
    await expect(create({ [mdlNamespace]: { age_in_years: 1 } })).rejects.toThrow(MissingRequestedElementError)
  })

  test('a holder with neither the element nor an alternative fails on the element', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [{ namespaces: { [mdlNamespace]: { age_in_years: false } }, requestInfo: ageInYearsOrAgeOver18 }],
    })

    const match = Holder.matchDeviceRequest({ deviceRequest, credentials: [await createIssuerSigned()] })

    expect(match.success).toBe(false)
  })

  test('the response discloses the alternative, and the verifier accepts it without an over-disclosure warning', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        {
          namespaces: { [mdlNamespace]: { family_name: false, age_in_years: false } },
          requestInfo: ageInYearsOrAgeOver18,
        },
      ],
    })
    const issuerSigned = await createIssuerSigned({ claims: { age_over_18: true } })

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [{ issuerSigned, docRequestIndex: 0, signature: { signingKey: deviceKey } }],
      },
      mdocContext
    )

    const disclosed = deviceResponse.documents?.[0].issuerSigned.getIssuerNamespace(mdlNamespace)
    expect(disclosed?.map((item) => item.elementIdentifier)).toStrictEqual(['family_name', 'age_over_18'])

    const checks: Array<VerificationAssessment> = []
    const result = await Verifier.verifyDeviceResponse(
      {
        deviceRequest,
        deviceResponse,
        sessionTranscript,
        trustedCertificates: [{ issuance: [issuerCertificate] }],
        disableStatusValidation: true,
        onCheck: (check) => checks.push(check),
      },
      mdocContext
    )

    expect(result.deviceRequestMatch?.success).toBe(true)
    expect(checks.filter((check) => check.status !== 'PASSED')).toStrictEqual([])
  })
})

describe('issuer identifiers', () => {
  test('a holder only answers with an mdoc of a named issuer', async () => {
    const credentials = [await createIssuerSigned()]
    const named = createDeviceRequest({
      docRequests: [
        {
          namespaces: { [mdlNamespace]: { family_name: false } },
          requestInfo: DocRequestInfo.create({ issuerIdentifiers: [issuerKeyIdentifier] }),
        },
      ],
    })
    const other = createDeviceRequest({
      docRequests: [
        {
          namespaces: { [mdlNamespace]: { family_name: false } },
          requestInfo: DocRequestInfo.create({ issuerIdentifiers: [hex.decode('00112233')] }),
        },
      ],
    })

    const accepted = Holder.matchDeviceRequest({ deviceRequest: named, credentials })
    assert(accepted.success)
    expect(accepted.docRequests[0].validCredentials[0]?.issuer).toStrictEqual({ success: true })

    const refused = Holder.matchDeviceRequest({ deviceRequest: other, credentials })
    expect(refused.success).toBe(false)
    expect(refused.docRequests[0].failedCredentials[0].issuer).toMatchObject({ success: false })
  })

  const namingAnotherIssuer = () =>
    createDeviceRequest({
      docRequests: [
        {
          namespaces: { [mdlNamespace]: { family_name: false } },
          requestInfo: DocRequestInfo.create({ issuerIdentifiers: [hex.decode('00112233')] }),
        },
      ],
    })

  test('a holder refuses to answer with an mdoc of an issuer the doc request does not name', async () => {
    await expect(
      Holder.createDeviceResponseForDeviceRequest(
        {
          deviceRequest: namingAnotherIssuer(),
          sessionTranscript,
          documents: [
            { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
          ],
        },
        mdocContext
      )
    ).rejects.toThrow(UnsatisfiedDeviceRequestError)
  })

  test('a verifier refuses a document from an issuer the doc request does not name', async () => {
    const deviceRequest = namingAnotherIssuer()
    // A holder that does not check the request information.
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest: createDeviceRequest({
          docRequests: [{ namespaces: { [mdlNamespace]: { family_name: false } } }],
        }),
        sessionTranscript,
        documents: [
          { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
        ],
      },
      mdocContext
    )

    const checks: Array<VerificationAssessment> = []
    await Verifier.verifyDeviceResponse(
      {
        deviceRequest,
        deviceResponse,
        sessionTranscript,
        trustedCertificates: [{ issuance: [issuerCertificate] }],
        disableStatusValidation: true,
        onCheck: (check) => checks.push(check),
      },
      mdocContext
    )

    const failed = checks.filter((check) => check.status === 'FAILED')
    expect(failed).toHaveLength(1)
    expect(failed[0].reason).toContain('issuer identifier')
  })
})

describe('unique document set', () => {
  const docRequest = { namespaces: { [mdlNamespace]: { family_name: false } } }
  const unique = () =>
    createDeviceRequest({
      docRequests: [{ ...docRequest, requestInfo: DocRequestInfo.create({ uniqueDocSetRequired: true }) }],
    })
  const twoDocuments = async () => [
    { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
    { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
  ]

  test('a holder refuses to answer a doc request that requires a unique document set with two documents', async () => {
    await expect(
      Holder.createDeviceResponseForDeviceRequest(
        { deviceRequest: unique(), sessionTranscript, documents: await twoDocuments() },
        mdocContext
      )
    ).rejects.toThrow(UnsatisfiedDeviceRequestError)
  })

  test('a verifier fails a doc request that requires a unique document set when two documents satisfy it', async () => {
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest: createDeviceRequest({ docRequests: [docRequest] }),
        sessionTranscript,
        documents: await twoDocuments(),
      },
      mdocContext
    )

    const match = Verifier.matchDeviceRequest({ deviceRequest: unique(), deviceResponse })

    expect(match.success).toBe(false)
    expect(match.docRequests[0]).toMatchObject({
      success: false,
      validDocuments: [{ documentIndex: 0 }, { documentIndex: 1 }],
      reason: 'Documents 0, 1 all satisfy doc request 0, but it requires a unique document set',
    })
  })
})

describe('use cases', () => {
  const mdlOrPhotoId = (mandatory = true) =>
    createDeviceRequest({
      docRequests: [
        { namespaces: { [mdlNamespace]: { family_name: false } } },
        { docType: photoIdDocType, namespaces: { [mdlNamespace]: { family_name: false } } },
      ],
      useCases: [{ mandatory, documentSets: [[0], [1]] }],
    })

  test('a holder with one of the documents satisfies "an mDL or a photo ID"', async () => {
    const match = Holder.matchDeviceRequest({
      deviceRequest: mdlOrPhotoId(),
      credentials: [await createIssuerSigned({ docType: photoIdDocType })],
    })

    expect(match).toMatchObject({
      success: true,
      useCasesSource: 'deviceRequestInfo',
      useCases: [{ useCaseIndex: 0, mandatory: true, success: true, documentSets: [[1]] }],
    })
  })

  test('every document set the holder can answer is listed, for the holder to pick one', async () => {
    const match = Holder.matchDeviceRequest({
      deviceRequest: mdlOrPhotoId(),
      credentials: [await createIssuerSigned({ docType: photoIdDocType }), await createIssuerSigned()],
    })

    expect(match.useCases[0].documentSets).toStrictEqual([[0], [1]])
  })

  test('a mandatory use case nothing satisfies fails the match, whatever treatAmbiguousMultipleDocRequestsAsAlternatives says', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        { namespaces: { [mdlNamespace]: { family_name: false } } },
        { docType: photoIdDocType, namespaces: { [mdlNamespace]: { family_name: false } } },
      ],
      useCases: [
        { mandatory: true, documentSets: [[1]] },
        { mandatory: false, documentSets: [[0]] },
      ],
    })

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [await createIssuerSigned()],
      treatAmbiguousMultipleDocRequestsAsAlternatives: true,
    })

    expect(match).toMatchObject({
      success: false,
      useCases: [
        { useCaseIndex: 0, mandatory: true, success: false, documentSets: [] },
        { useCaseIndex: 1, mandatory: false, success: true, documentSets: [[0]] },
      ],
    })
  })

  test('a verifier accepts the response answering one document set, and reports the use case', async () => {
    const deviceRequest = mdlOrPhotoId()
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
        ],
      },
      mdocContext
    )

    const checks: Array<VerificationAssessment> = []
    const result = await Verifier.verifyDeviceResponse(
      {
        deviceRequest,
        deviceResponse,
        sessionTranscript,
        trustedCertificates: [{ issuance: [issuerCertificate] }],
        disableStatusValidation: true,
        onCheck: (check) => checks.push(check),
      },
      mdocContext
    )

    expect(result.deviceRequestMatch).toMatchObject({
      success: true,
      useCases: [{ success: true, documentSets: [[0]] }],
    })
    expect(checks.filter((check) => check.status !== 'PASSED')).toStrictEqual([])
    expect(checks.map((check) => check.check)).toContain('Device response must satisfy mandatory use case 0')
  })

  const mandatoryPhotoIdOptionalMdl = () =>
    createDeviceRequest({
      docRequests: [
        { namespaces: { [mdlNamespace]: { family_name: false } } },
        { docType: photoIdDocType, namespaces: { [mdlNamespace]: { family_name: false } } },
      ],
      useCases: [
        { mandatory: true, documentSets: [[1]] },
        { mandatory: false, documentSets: [[0]] },
      ],
    })

  test('a holder refuses a response that leaves a mandatory use case unsatisfied, but may send nothing', async () => {
    const deviceRequest = mandatoryPhotoIdOptionalMdl()

    await expect(
      Holder.createDeviceResponseForDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [
            { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
          ],
        },
        mdocContext
      )
    ).rejects.toThrow(UnsatisfiedDeviceRequestError)

    const declined = await Holder.createDeviceResponseForDeviceRequest(
      { deviceRequest, sessionTranscript, documents: [] },
      mdocContext
    )
    expect(declined.documents ?? []).toHaveLength(0)
  })

  test('a holder may leave out elements of a mandatory use case, only the documents are checked', async () => {
    const deviceRequest = mandatoryPhotoIdOptionalMdl()

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          {
            issuerSigned: await createIssuerSigned({ docType: photoIdDocType }),
            docRequestIndex: 1,
            elements: {},
            signature: { signingKey: deviceKey },
          },
        ],
      },
      mdocContext
    )

    expect(deviceResponse.documents).toHaveLength(1)
  })

  test('without use cases, the doc requests are one mandatory use case, or optional ones as alternatives', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        { namespaces: { [mdlNamespace]: { family_name: false } } },
        { docType: photoIdDocType, namespaces: { [mdlNamespace]: { family_name: false } } },
      ],
    })
    const credentials = [await createIssuerSigned()]

    expect(Holder.matchDeviceRequest({ deviceRequest, credentials })).toMatchObject({
      success: false,
      useCasesSource: 'allDocRequests',
      useCases: [{ mandatory: true, success: false, documentSets: [] }],
    })
    expect(
      Holder.matchDeviceRequest({ deviceRequest, credentials, treatAmbiguousMultipleDocRequestsAsAlternatives: true })
    ).toMatchObject({
      success: true,
      useCasesSource: 'eachDocRequest',
      useCases: [
        { mandatory: false, success: true, documentSets: [[0]] },
        { mandatory: false, success: false, documentSets: [] },
      ],
    })
    expect(
      Holder.matchDeviceRequest({
        deviceRequest,
        credentials: [],
        treatAmbiguousMultipleDocRequestsAsAlternatives: true,
      }).success
    ).toBe(false)
  })

  test('without use cases, a holder is not held to any doc request', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        { namespaces: { [mdlNamespace]: { family_name: false } } },
        { docType: photoIdDocType, namespaces: { [mdlNamespace]: { family_name: false } } },
      ],
    })

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
        ],
      },
      mdocContext
    )

    expect(deviceResponse.documents).toHaveLength(1)
  })
})
