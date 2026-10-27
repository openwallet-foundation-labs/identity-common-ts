import 'reflect-metadata'
import nodeCrypto from 'node:crypto'
import { hex } from '@owf/identity-common'
import * as x509 from '@peculiar/x509'
import { assert, describe, expect, test } from 'vitest'
import { z } from 'zod'
import {
  CoseKey,
  DeviceKey,
  DeviceRequest,
  DeviceRequestInfo,
  type DeviceRequestMatchResult,
  DeviceResponse,
  type DeviceResponseDocumentOptions,
  DocRequest,
  DocRequestInfo,
  DocTypeMismatchError,
  Holder,
  InvalidElementSelectionError,
  Issuer,
  type IssuerSigned,
  ItemsRequest,
  MissingRequestedElementError,
  RegisteredCwtHeaderClaimKey,
  reportDeviceRequestMatch,
  SessionTranscript,
  SignatureAlgorithm,
  UnsatisfiedDeviceRequestError,
  type VerificationAssessment,
  Verifier,
} from '../..'
import { Handover } from '../../mdoc/models/handover'
import { DEVICE_JWK_PRIVATE, DEVICE_JWK_PUBLIC, ISSUER_CERTIFICATE } from '../config'
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

x509.cryptoProvider.set(nodeCrypto.webcrypto as unknown as Crypto)

const issuerKeyIdentifier = hex.decode(
  new x509.X509Certificate(ISSUER_CERTIFICATE).getExtension(x509.AuthorityKeyIdentifierExtension)?.keyId ?? ''
)

const createDeviceRequest = (options: {
  docRequests: Array<{
    docType?: string
    namespaces: Record<string, Record<string, boolean>>
    requestInfo?: DocRequestInfo
  }>
  useCases?: Array<{ mandatory: boolean; documentSets: Array<Array<number>>; purposeHints?: Map<string, number> }>
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
    // The first option is the element itself, so it has no alternativeElementSetIndex.
    expect(claim?.options?.[0]).toStrictEqual({
      elements: [
        { namespace: mdlNamespace, elementIdentifier: 'age_in_years', elementValue: 36, source: 'issuerSigned' },
      ],
    })
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

  describe('an element left out is not disclosed through an alternative set', () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        {
          namespaces: { [mdlNamespace]: { age_in_years: false, age_over_18: false } },
          requestInfo: ageInYearsOrAgeOver18,
        },
      ],
    })
    const create = async (
      claims: Record<string, unknown>,
      elements: Record<string, Array<string>>,
      alternatives?: Record<string, Record<string, number>>
    ) =>
      Holder.createDeviceResponseForDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [
            {
              issuerSigned: await createIssuerSigned({ claims }),
              docRequestIndex: 0,
              elements,
              alternatives,
              signature: { signingKey: deviceKey },
            },
          ],
        },
        mdocContext
      )
    const leftOut = new InvalidElementSelectionError(
      `Element 'age_in_years' in namespace '${mdlNamespace}' is selected for disclosure, but it is answered with alternative set 1, which discloses 'age_over_18' in namespace '${mdlNamespace}' that is not selected. Select both, or choose another alternative set`
    )

    test('chosen by the holder', async () => {
      await expect(
        create(
          { age_in_years: 36, age_over_18: true },
          { [mdlNamespace]: ['age_in_years'] },
          { [mdlNamespace]: { age_in_years: 1 } }
        )
      ).rejects.toThrow(leftOut)
    })

    test('chosen for an element the credential does not have', async () => {
      await expect(
        create({ age_over_18: true }, { [mdlNamespace]: ['age_in_years'] }, { [mdlNamespace]: { age_in_years: 1 } })
      ).rejects.toThrow(leftOut)
    })

    test('a requested element answered by an alternative set can be left out while that set is disclosed', async () => {
      const deviceResponse = await create({ age_over_18: true }, { [mdlNamespace]: ['age_over_18'] })

      const disclosed = deviceResponse.documents?.[0].issuerSigned.getIssuerNamespace(mdlNamespace)
      expect(disclosed?.map((item) => item.elementIdentifier)).toStrictEqual(['age_over_18'])
    })
  })

  test('a holder does not disclose an alternative set it did not choose', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [{ namespaces: { [mdlNamespace]: { age_in_years: false } }, requestInfo: ageInYearsOrAgeOver18 }],
    })

    await expect(
      Holder.createDeviceResponseForDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [
            {
              issuerSigned: await createIssuerSigned({ claims: { age_over_18: true } }),
              docRequestIndex: 0,
              signature: { signingKey: deviceKey },
            },
          ],
        },
        mdocContext
      )
    ).rejects.toThrow(
      new MissingRequestedElementError(
        `Element 'age_in_years' in namespace '${mdlNamespace}' is not in the credential. Choose one of its alternative sets 1 with \`alternatives\` to disclose in its place`
      )
    )
  })

  test('a holder cannot choose an alternative set for an element the doc request does not request', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [{ namespaces: { [mdlNamespace]: { age_over_18: false } }, requestInfo: ageInYearsOrAgeOver18 }],
    })

    await expect(
      Holder.createDeviceResponseForDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [
            {
              issuerSigned: await createIssuerSigned({ claims: { age_over_18: true } }),
              docRequestIndex: 0,
              alternatives: { [mdlNamespace]: { age_in_years: 1 } },
              signature: { signingKey: deviceKey },
            },
          ],
        },
        mdocContext
      )
    ).rejects.toThrow(
      new InvalidElementSelectionError(
        `Alternative set 1 of element 'age_in_years' in namespace '${mdlNamespace}' is selected for disclosure, but the doc request does not request the element`
      )
    )
  })

  test('the elements of an alternative set are requested too, so the verifier does not report them as over-disclosure', async () => {
    // The holder answers 'age_in_years' with the second set, while the first set is disclosed for
    // its own request.
    const deviceRequest = createDeviceRequest({
      docRequests: [
        {
          namespaces: { [mdlNamespace]: { age_in_years: false, age_birth_year: false } },
          requestInfo: ageInYearsOrAgeOver18,
        },
      ],
    })
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          {
            issuerSigned: await createIssuerSigned({ claims: { age_birth_year: 1990, age_over_18: true } }),
            docRequestIndex: 0,
            alternatives: { [mdlNamespace]: { age_in_years: 1 } },
            signature: { signingKey: deviceKey },
          },
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

    expect(result.deviceRequestMatch?.success).toBe(true)
    expect(checks.filter((check) => check.status !== 'PASSED')).toStrictEqual([])
  })

  describe('at most two age_over_NN elements are disclosed in a namespace (18013-5 7.2.5)', () => {
    const credentials = async () => [
      await createIssuerSigned({ claims: { age_over_18: true, age_over_21: true, age_over_65: false } }),
    ]
    const failedClaim = (match: ReturnType<typeof Holder.matchDeviceRequest>) =>
      match.docRequests[0].failedCredentials[0]?.claims.failedClaims[0]

    test('an alternative set that would disclose a third one with the other requested elements is not offered', async () => {
      const deviceRequest = createDeviceRequest({
        docRequests: [
          {
            namespaces: { [mdlNamespace]: { age_over_18: false, age_over_21: false, age_in_years: false } },
            requestInfo: DocRequestInfo.create({
              alternativeDataElements: [
                {
                  requestedElement: [mdlNamespace, 'age_in_years'],
                  alternativeElementSets: [[[mdlNamespace, 'age_over_65']]],
                },
              ],
            }),
          },
        ],
      })

      const match = Holder.matchDeviceRequest({ deviceRequest, credentials: await credentials() })

      expect(match.success).toBe(false)
      expect(failedClaim(match)).toMatchObject({
        elementIdentifier: 'age_in_years',
        reason: `Element 'age_in_years' in namespace '${mdlNamespace}' is not in the credential, and each of its alternative sets the credential has would disclose more than two age_over_NN elements in a namespace`,
      })
    })

    test('an alternative set of three is not offered', async () => {
      const deviceRequest = createDeviceRequest({
        docRequests: [
          {
            namespaces: { [mdlNamespace]: { age_in_years: false } },
            requestInfo: DocRequestInfo.create({
              alternativeDataElements: [
                {
                  requestedElement: [mdlNamespace, 'age_in_years'],
                  alternativeElementSets: [
                    [
                      [mdlNamespace, 'age_over_18'],
                      [mdlNamespace, 'age_over_21'],
                      [mdlNamespace, 'age_over_65'],
                    ],
                  ],
                },
              ],
            }),
          },
        ],
      })

      const match = Holder.matchDeviceRequest({ deviceRequest, credentials: await credentials() })

      expect(match.success).toBe(false)
      expect(failedClaim(match)).toMatchObject({ elementIdentifier: 'age_in_years' })
    })
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
      reason:
        'Doc request 0 requires a unique document set, but the response has more documents than such doc requests can take: documents 0, 1 may only answer doc request 0',
    })
  })

  test('a verifier counts a document of the docType of another doc request for that one, even with elements left out', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        { ...docRequest, requestInfo: DocRequestInfo.create({ uniqueDocSetRequired: true }) },
        { namespaces: { [mdlNamespace]: { family_name: false, given_name: false } } },
      ],
      useCases: [
        { mandatory: true, documentSets: [[0]] },
        { mandatory: false, documentSets: [[1]] },
      ],
    })
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
          {
            issuerSigned: await createIssuerSigned(),
            docRequestIndex: 1,
            elements: { [mdlNamespace]: ['family_name'] },
            signature: { signingKey: deviceKey },
          },
        ],
      },
      mdocContext
    )

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })
    expect(match.success).toBe(true)
    // Document 1 answers the optional use case with given_name left out, which is no reason to warn.
    const checks: Array<VerificationAssessment> = []
    reportDeviceRequestMatch(match, (check) => checks.push(check))
    expect(checks.filter((check) => check.status !== 'PASSED')).toStrictEqual([])
  })

  test('a verifier counts a document that also satisfies another doc request for that one', async () => {
    // Two mDL doc requests, the second also asking for what the first asks.
    const deviceRequest = createDeviceRequest({
      docRequests: [
        { ...docRequest, requestInfo: DocRequestInfo.create({ uniqueDocSetRequired: true }) },
        { namespaces: { [mdlNamespace]: { family_name: false, given_name: false } } },
      ],
    })
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
          { issuerSigned: await createIssuerSigned(), docRequestIndex: 1, signature: { signingKey: deviceKey } },
        ],
      },
      mdocContext
    )

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(true)
    expect(match.docRequests[0]).toMatchObject({
      success: true,
      validDocuments: [{ documentIndex: 0 }, { documentIndex: 1 }],
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
      useCases: [
        { useCaseIndex: 0, mandatory: true, success: true, documentSets: [[0], [1]], matchingDocumentSets: [[1]] },
      ],
    })
  })

  test('every document set the holder can answer is listed, for the holder to pick one', async () => {
    const match = Holder.matchDeviceRequest({
      deviceRequest: mdlOrPhotoId(),
      credentials: [await createIssuerSigned({ docType: photoIdDocType }), await createIssuerSigned()],
    })

    expect(match.useCases[0].matchingDocumentSets).toStrictEqual([[0], [1]])
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
        { useCaseIndex: 0, mandatory: true, success: false, documentSets: [[1]], matchingDocumentSets: [] },
        { useCaseIndex: 1, mandatory: false, success: true, documentSets: [[0]], matchingDocumentSets: [[0]] },
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
      useCases: [{ success: true, documentSets: [[0], [1]], matchingDocumentSets: [[0]] }],
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

  test('a holder refuses a response that answers none of the use cases, and says which doc requests it answers', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        { namespaces: { [mdlNamespace]: { family_name: false } } },
        { docType: photoIdDocType, namespaces: { [mdlNamespace]: { family_name: false } } },
      ],
      useCases: [{ mandatory: false, documentSets: [[0, 1]] }],
    })

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
    ).rejects.toThrow(
      new UnsatisfiedDeviceRequestError(
        'None of the use cases has a document set whose doc requests the documents all answer (they answer doc requests 0)'
      )
    )
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
      useCases: [{ mandatory: true, success: false, documentSets: [[0, 1]], matchingDocumentSets: [] }],
    })
    expect(
      Holder.matchDeviceRequest({ deviceRequest, credentials, treatAmbiguousMultipleDocRequestsAsAlternatives: true })
    ).toMatchObject({
      success: true,
      useCasesSource: 'eachDocRequest',
      useCases: [
        { mandatory: false, success: true, documentSets: [[0]], matchingDocumentSets: [[0]] },
        { mandatory: false, success: false, documentSets: [[1]], matchingDocumentSets: [] },
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

describe('issuer identifiers against a certificate chain', () => {
  const generateKeys = async () =>
    (await nodeCrypto.webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])) as unknown as CryptoKeyPair

  /** An IACA, and a document signer certificate it issued, with their key identifier extensions. */
  const createIssuer = async (country: string) => {
    const iacaKeys = await generateKeys()
    const documentSignerKeys = await generateKeys()
    const notBefore = new Date(Date.now() - 60 * 60 * 1000)
    const notAfter = new Date(Date.now() + 60 * 60 * 1000)

    const iaca = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01',
      name: `C=${country}, CN=IACA ${country}`,
      notBefore,
      notAfter,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      keys: iacaKeys,
      extensions: [
        new x509.BasicConstraintsExtension(true, 0, true),
        await x509.SubjectKeyIdentifierExtension.create(iacaKeys.publicKey),
      ],
    })
    const documentSigner = await x509.X509CertificateGenerator.create({
      serialNumber: '02',
      issuer: iaca.subject,
      subject: `C=${country}, CN=DS ${country}`,
      notBefore,
      notAfter,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      publicKey: documentSignerKeys.publicKey,
      signingKey: iacaKeys.privateKey,
      extensions: [
        await x509.SubjectKeyIdentifierExtension.create(documentSignerKeys.publicKey),
        await x509.AuthorityKeyIdentifierExtension.create(iaca),
      ],
    })

    const { kty, crv, x, y, d } = (await nodeCrypto.webcrypto.subtle.exportKey(
      'jwk',
      documentSignerKeys.privateKey
    )) as Record<string, unknown>
    const keyIdentifier = (certificate: x509.X509Certificate) =>
      hex.decode(certificate.getExtension(x509.SubjectKeyIdentifierExtension)?.keyId ?? '')

    return {
      iaca: new Uint8Array(iaca.rawData),
      documentSigner: new Uint8Array(documentSigner.rawData),
      iacaKeyIdentifier: keyIdentifier(iaca),
      documentSignerKeyIdentifier: keyIdentifier(documentSigner),
      signingKey: CoseKey.fromJwk({ kty, crv, x, y, d, alg: 'ES256' }),
    }
  }

  const sign = async ({ signingKey, documentSigner }: Awaited<ReturnType<typeof createIssuer>>) => {
    const issuer = new Issuer(mdlDocType, mdocContext)
    issuer.addIssuerNamespace(mdlNamespace, { family_name: 'Doe' })
    const signed = new Date(Date.now() - 60_000)
    return issuer.sign({
      signingKey,
      certificates: [documentSigner],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom: signed, validUntil: new Date(Date.now() + 60 * 60 * 1000) },
    })
  }

  const naming = (issuerIdentifier: Uint8Array) =>
    createDeviceRequest({
      docRequests: [
        {
          namespaces: { [mdlNamespace]: { family_name: false } },
          requestInfo: DocRequestInfo.create({ issuerIdentifiers: [issuerIdentifier] }),
        },
      ],
    })

  const verify = async (deviceRequest: DeviceRequest, issuerSigned: IssuerSigned, trusted: Uint8Array) => {
    // A holder that does not check the request information.
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest: createDeviceRequest({
          docRequests: [{ namespaces: { [mdlNamespace]: { family_name: false } } }],
        }),
        sessionTranscript,
        documents: [{ issuerSigned, docRequestIndex: 0, signature: { signingKey: deviceKey } }],
      },
      mdocContext
    )
    const checks: Array<VerificationAssessment> = []
    const result = await Verifier.verifyDeviceResponse(
      {
        deviceRequest,
        deviceResponse,
        sessionTranscript,
        trustedCertificates: [{ issuance: [trusted] }],
        disableStatusValidation: true,
        onCheck: (check) => checks.push(check),
      },
      mdocContext
    )
    return { deviceResponse, match: result.deviceRequestMatch, failed: checks.filter((c) => c.status === 'FAILED') }
  }

  test('an mdoc matches the IACA it was issued under, through the authority key identifier of its document signer certificate', async () => {
    const issuer = await createIssuer('FR')

    const { match, failed } = await verify(naming(issuer.iacaKeyIdentifier), await sign(issuer), issuer.iaca)

    expect(match?.success).toBe(true)
    expect(failed).toStrictEqual([])
  })

  test('a holder answers with an mdoc of the IACA the doc request names, matched against its x5chain', async () => {
    const issuer = await createIssuer('FR')
    const other = await createIssuer('DE')
    const issuerSigned = await sign(issuer)
    const respond = (deviceRequest: DeviceRequest) =>
      Holder.createDeviceResponseForDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [{ issuerSigned, docRequestIndex: 0, signature: { signingKey: deviceKey } }],
        },
        mdocContext
      )

    await expect(respond(naming(issuer.iacaKeyIdentifier))).resolves.toBeInstanceOf(DeviceResponse)
    await expect(respond(naming(other.iacaKeyIdentifier))).rejects.toThrow(UnsatisfiedDeviceRequestError)
  })

  test('a credential without an x5chain does not match a doc request that names issuers', async () => {
    const issuer = await createIssuer('FR')
    const issuerSigned = await sign(issuer)
    issuerSigned.issuerAuth.unprotectedHeaders.headers.delete(RegisteredCwtHeaderClaimKey.X5Chain)

    const match = Holder.matchDeviceRequest({
      deviceRequest: naming(issuer.iacaKeyIdentifier),
      credentials: [issuerSigned],
    })

    expect(match.success).toBe(false)
    expect(match.docRequests[0].failedCredentials[0].issuer).toMatchObject({ success: false })
  })

  test('the subject key identifier of the document signer certificate does not name its issuer', async () => {
    const issuer = await createIssuer('FR')

    const match = Holder.matchDeviceRequest({
      deviceRequest: naming(issuer.documentSignerKeyIdentifier),
      credentials: [await sign(issuer)],
    })

    expect(match.success).toBe(false)
  })

  test('a certificate added to the unprotected x5chain does not make an mdoc pass for another issuer', async () => {
    const issuer = await createIssuer('FR')
    const other = await createIssuer('DE')
    const issuerSigned = await sign(issuer)
    // The x5chain is not signed: anyone can add the document signer certificate of another issuer.
    issuerSigned.issuerAuth.unprotectedHeaders.headers.set(RegisteredCwtHeaderClaimKey.X5Chain, [
      issuer.documentSigner,
      other.documentSigner,
    ])
    const deviceRequest = naming(other.iacaKeyIdentifier)

    const { deviceResponse, match, failed } = await verify(deviceRequest, issuerSigned, issuer.iaca)

    expect(match?.success).toBe(false)
    expect(failed.map((check) => check.reason).join(' ')).toContain('validated certificate chain')
    // Without validated chains, the verifier does not fall back to the x5chain.
    const unvalidated = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })
    expect(unvalidated.success).toBe(false)
    expect(unvalidated.docRequests[0].failedDocuments[0]).toMatchObject({
      issuer: { success: false, reason: expect.stringContaining('has no validated certificate chain') },
    })
  })

  test('an mdoc whose chain does not validate does not match its issuer', async () => {
    const issuer = await createIssuer('FR')
    const other = await createIssuer('DE')

    const { match } = await verify(naming(issuer.iacaKeyIdentifier), await sign(issuer), other.iaca)

    expect(match?.success).toBe(false)
    expect(match?.docRequests[0].failedDocuments[0]).toMatchObject({
      issuer: { success: false, reason: expect.stringContaining('has no validated certificate chain') },
    })
  })
  test('a verifier gives each document its own doc request when two require a unique document set', async () => {
    const fr = await createIssuer('FR')
    const de = await createIssuer('DE')
    const deviceRequest = createDeviceRequest({
      docRequests: [
        {
          namespaces: { [mdlNamespace]: { family_name: false } },
          requestInfo: DocRequestInfo.create({ uniqueDocSetRequired: true }),
        },
        {
          namespaces: { [mdlNamespace]: { family_name: false } },
          requestInfo: DocRequestInfo.create({ uniqueDocSetRequired: true, issuerIdentifiers: [fr.iacaKeyIdentifier] }),
        },
      ],
    })
    // The French mDL satisfies both doc requests and comes first, the German one only the first.
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest: createDeviceRequest({
          docRequests: [{ namespaces: { [mdlNamespace]: { family_name: false } } }],
        }),
        sessionTranscript,
        documents: [
          { issuerSigned: await sign(fr), docRequestIndex: 0, signature: { signingKey: deviceKey } },
          { issuerSigned: await sign(de), docRequestIndex: 0, signature: { signingKey: deviceKey } },
        ],
      },
      mdocContext
    )

    const match = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      issuerCertificateChains: [
        [fr.documentSigner, fr.iaca],
        [de.documentSigner, de.iaca],
      ],
    })

    expect(match.success).toBe(true)
    expect(match.attribution.documents).toStrictEqual([
      { documentIndex: 0, docRequestIndexes: [1] },
      { documentIndex: 1, docRequestIndexes: [0] },
    ])
  })

  test('which doc requests fail for one document too many does not depend on the order of the documents', async () => {
    const fr = await createIssuer('FR')
    const de = await createIssuer('DE')
    const deviceRequest = createDeviceRequest({
      docRequests: [
        {
          namespaces: { [mdlNamespace]: { family_name: false } },
          requestInfo: DocRequestInfo.create({ uniqueDocSetRequired: true, issuerIdentifiers: [fr.iacaKeyIdentifier] }),
        },
        {
          namespaces: { [mdlNamespace]: { family_name: false } },
          requestInfo: DocRequestInfo.create({ uniqueDocSetRequired: true }),
        },
      ],
      useCases: [
        { mandatory: true, documentSets: [[0]] },
        { mandatory: false, documentSets: [[1]] },
      ],
    })
    const french = [await sign(fr), await sign(fr)]
    const german = await sign(de)
    const chains = new Map([
      [fr, [fr.documentSigner, fr.iaca]],
      [de, [de.documentSigner, de.iaca]],
    ])

    const verify = async (documents: Array<[IssuerSigned, Awaited<ReturnType<typeof createIssuer>>]>) => {
      const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
        {
          deviceRequest: createDeviceRequest({
            docRequests: [{ namespaces: { [mdlNamespace]: { family_name: false } } }],
          }),
          sessionTranscript,
          documents: documents.map(([issuerSigned]) => ({
            issuerSigned,
            docRequestIndex: 0,
            signature: { signingKey: deviceKey },
          })),
        },
        mdocContext
      )
      const match = Verifier.matchDeviceRequest({
        deviceRequest,
        deviceResponse,
        issuerCertificateChains: documents.map(([, issuer]) => chains.get(issuer)),
      })
      return { success: match.success, docRequests: match.docRequests.map((docRequest) => docRequest.success) }
    }

    // Three documents for two doc requests that take one each, whichever comes first.
    const expected = { success: false, docRequests: [false, false] }
    expect(
      await verify([
        [french[0], fr],
        [french[1], fr],
        [german, de],
      ])
    ).toStrictEqual(expected)
    expect(
      await verify([
        [german, de],
        [french[0], fr],
        [french[1], fr],
      ])
    ).toStrictEqual(expected)
  })

  test('a doc request that takes one document fails when the one it has to take does not satisfy it', async () => {
    const fr = await createIssuer('FR')
    const de = await createIssuer('DE')
    const deviceRequest = createDeviceRequest({
      docRequests: [
        {
          namespaces: { [mdlNamespace]: { family_name: false, given_name: false } },
          requestInfo: DocRequestInfo.create({ uniqueDocSetRequired: true }),
        },
        {
          namespaces: { [mdlNamespace]: { family_name: false } },
          requestInfo: DocRequestInfo.create({ issuerIdentifiers: [fr.iacaKeyIdentifier] }),
        },
      ],
      useCases: [
        { mandatory: false, documentSets: [[0]] },
        { mandatory: false, documentSets: [[1]] },
      ],
    })
    // Only the first doc request may take the German mDL, which lacks given_name, so it cannot take
    // the French one that satisfies it.
    const issuer = new Issuer(mdlDocType, mdocContext)
    issuer.addIssuerNamespace(mdlNamespace, { family_name: 'Doe', given_name: 'John' })
    const signed = new Date(Date.now() - 60_000)
    const full = await issuer.sign({
      signingKey: fr.signingKey,
      certificates: [fr.documentSigner],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom: signed, validUntil: new Date(Date.now() + 60 * 60 * 1000) },
    })
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest: createDeviceRequest({
          docRequests: [{ namespaces: { [mdlNamespace]: { family_name: false, given_name: false } } }],
        }),
        sessionTranscript,
        documents: [
          {
            issuerSigned: await sign(de),
            docRequestIndex: 0,
            elements: { [mdlNamespace]: ['family_name'] },
            signature: { signingKey: deviceKey },
          },
          { issuerSigned: full, docRequestIndex: 0, signature: { signingKey: deviceKey } },
        ],
      },
      mdocContext
    )

    const match = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      issuerCertificateChains: [
        [de.documentSigner, de.iaca],
        [fr.documentSigner, fr.iaca],
      ],
    })

    expect(match.success).toBe(true)
    expect(match.docRequests[0]).toMatchObject({
      success: false,
      validDocuments: [{ documentIndex: 1 }],
      reason:
        'Doc request 0 requires a unique document set, and the documents that only doc requests like it may answer leave it none of documents 1, which satisfy it',
    })
    expect(match.attribution.useCases).toStrictEqual([{ useCaseIndex: 1, documentSet: [1] }])
  })
})

describe('response checks', () => {
  const familyName = { namespaces: { [mdlNamespace]: { family_name: false } } }
  const respond = async (
    deviceRequest: DeviceRequest,
    docRequestIndex: number | Array<number> = 0,
    docType = mdlDocType
  ) =>
    Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          {
            issuerSigned: await createIssuerSigned({ docType }),
            docRequestIndex,
            signature: { signingKey: deviceKey },
          },
        ],
      },
      mdocContext
    )

  test('a holder refuses a response larger than the maximumResponseSize of a doc request', async () => {
    const limited = (maximumResponseSize: number) =>
      createDeviceRequest({
        docRequests: [{ ...familyName, requestInfo: DocRequestInfo.create({ maximumResponseSize }) }],
      })

    await expect(respond(limited(100))).rejects.toThrow(UnsatisfiedDeviceRequestError)
    await expect(respond(limited(100))).rejects.toThrow(/accepts at most 100\. Leave out elements or documents$/)
    await expect(respond(limited(100_000))).resolves.toBeDefined()
  })

  test('a holder may answer two doc requests of a document set with one document that names both', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [{ namespaces: { [mdlNamespace]: { family_name: false, given_name: false } } }, familyName],
      useCases: [{ mandatory: true, documentSets: [[0, 1]] }],
    })

    await expect(respond(deviceRequest)).rejects.toThrow(
      new UnsatisfiedDeviceRequestError(
        'Use case 0 is mandatory, but the documents do not answer every doc request of any of its document sets (they answer doc requests 0)'
      )
    )
    const deviceResponse = await respond(deviceRequest, [0, 1])

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })
    expect(match.success).toBe(true)
    expect(match.attribution).toStrictEqual({
      useCases: [{ useCaseIndex: 0, documentSet: [0, 1] }],
      documents: [{ documentIndex: 0, docRequestIndexes: [0, 1] }],
    })
  })

  test('a document for a doc request that does not exist is refused as such', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [familyName],
      useCases: [{ mandatory: true, documentSets: [[0]] }],
    })

    await expect(respond(deviceRequest, 5, photoIdDocType)).rejects.toThrow(
      new Error('No doc request found at index 5')
    )
  })

  test('a use case reports its purpose hints', async () => {
    const purposeHints = new Map([['org.example.purposes', 3]])
    const match = Holder.matchDeviceRequest({
      deviceRequest: createDeviceRequest({
        docRequests: [familyName],
        useCases: [{ mandatory: true, documentSets: [[0]], purposeHints }],
      }),
      credentials: [await createIssuerSigned()],
    })

    expect(match.useCases[0]).toStrictEqual({
      useCaseIndex: 0,
      mandatory: true,
      purposeHints,
      success: true,
      documentSets: [[0]],
      matchingDocumentSets: [[0]],
    })
  })

  test('a failed use case reports the doc requests of its document sets', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [familyName, { ...familyName, docType: photoIdDocType }],
      useCases: [
        { mandatory: true, documentSets: [[1]] },
        { mandatory: false, documentSets: [[0]] },
      ],
    })
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      { deviceRequest, sessionTranscript, documents: [] },
      mdocContext
    )

    const checks: Array<VerificationAssessment> = []
    reportDeviceRequestMatch(Verifier.matchDeviceRequest({ deviceRequest, deviceResponse }), (check) =>
      checks.push(check)
    )
    const reason = (check: string) => checks.find((c) => c.check === check)?.reason

    expect(reason('Device response must satisfy mandatory use case 0')).toMatch(/Doc request 1: /)
    expect(reason('Device response must satisfy mandatory use case 0')).not.toMatch(/Doc request 0: /)
    expect(reason('Device response must satisfy at least one use case')).toMatch(
      /^No use case is satisfied\. Doc request 0: .*Doc request 1: /
    )
  })
})

describe('attribution', () => {
  const familyName = { namespaces: { [mdlNamespace]: { family_name: false } } }
  const respond = async (
    deviceRequest: DeviceRequest,
    documents: Array<{ docRequestIndex: number | Array<number>; docType?: string }>
  ) =>
    Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: await Promise.all(
          documents.map(async ({ docRequestIndex, docType }) => ({
            issuerSigned: await createIssuerSigned({ docType }),
            docRequestIndex,
            signature: { signingKey: deviceKey },
          }))
        ),
      },
      mdocContext
    )
  const verify = async (deviceRequest: DeviceRequest, deviceResponse: DeviceResponse) => {
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
    return { match: result.deviceRequestMatch, checks: checks.filter((check) => check.status !== 'PASSED') }
  }

  test('two doc requests that require a unique document set take one document each', async () => {
    const unique = { ...familyName, requestInfo: DocRequestInfo.create({ uniqueDocSetRequired: true }) }
    const deviceRequest = createDeviceRequest({ docRequests: [unique, unique] })

    const { match, checks } = await verify(
      deviceRequest,
      await respond(deviceRequest, [{ docRequestIndex: 0 }, { docRequestIndex: 1 }])
    )
    expect(checks).toStrictEqual([])
    expect(match?.attribution.documents).toStrictEqual([
      { documentIndex: 0, docRequestIndexes: [0] },
      { documentIndex: 1, docRequestIndexes: [1] },
    ])

    // A third document is one too many for them.
    const plain = createDeviceRequest({ docRequests: [familyName] })
    const three = await respond(plain, [{ docRequestIndex: 0 }, { docRequestIndex: 0 }, { docRequestIndex: 0 }])
    const failed = await verify(deviceRequest, three)
    expect(failed.match?.success).toBe(false)
    expect(failed.match?.docRequests.map((docRequest) => docRequest.success)).toStrictEqual([false, false])
    expect(failed.match?.docRequests[0]).toMatchObject({
      reason:
        'Doc request 0 requires a unique document set, but the response has more documents than such doc requests can take: documents 0, 1, 2 may only answer doc requests 0, 1, which all do',
    })
  })

  test('a document of a document set the use case is not answered with is reported as a warning', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [familyName, { ...familyName, docType: photoIdDocType }],
      useCases: [{ mandatory: true, documentSets: [[0], [1]] }],
    })

    const { match, checks } = await verify(
      deviceRequest,
      await respond(deviceRequest, [{ docRequestIndex: 0 }, { docRequestIndex: 1, docType: photoIdDocType }])
    )

    expect(match?.success).toBe(true)
    expect(match?.attribution).toStrictEqual({
      useCases: [{ useCaseIndex: 0, documentSet: [0] }],
      documents: [
        { documentIndex: 0, docRequestIndexes: [0] },
        { documentIndex: 1, docRequestIndexes: [1] },
      ],
    })
    expect(checks).toStrictEqual([
      {
        status: 'WARNING',
        check: 'Device response must only contain documents of one document set per use case',
        category: 'DOCUMENT_FORMAT',
        reason:
          'Document 1 answers no doc request of the document sets the use cases are answered with (use case 0 with doc requests 0)',
      },
    ])
  })

  test('a use case is taken to be answered with the satisfied document set the most documents answer', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [familyName, { ...familyName, docType: photoIdDocType }],
      useCases: [{ mandatory: true, documentSets: [[0], [0, 1]] }],
    })

    const { match, checks } = await verify(
      deviceRequest,
      await respond(deviceRequest, [{ docRequestIndex: 0 }, { docRequestIndex: 1, docType: photoIdDocType }])
    )

    expect(checks).toStrictEqual([])
    expect(match?.attribution.useCases).toStrictEqual([{ useCaseIndex: 0, documentSet: [0, 1] }])
  })
})

describe('attribution, order and satisfaction', () => {
  const unique = DocRequestInfo.create({ uniqueDocSetRequired: true })
  const withClaims = async (claims: Array<string>, docRequestIndex: number) => ({
    issuerSigned: await createIssuerSigned(),
    docRequestIndex,
    elements: { [mdlNamespace]: claims },
    signature: { signingKey: deviceKey },
  })

  test('a doc request that takes one document takes one that satisfies it when there is one', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        { namespaces: { [mdlNamespace]: { family_name: false } }, requestInfo: unique },
        { namespaces: { [mdlNamespace]: { family_name: false, given_name: false } }, requestInfo: unique },
      ],
    })
    // The full document for the second doc request comes first.
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [await withClaims(['family_name', 'given_name'], 1), await withClaims(['family_name'], 0)],
      },
      mdocContext
    )

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(true)
    expect(match.attribution.documents).toStrictEqual([
      { documentIndex: 0, docRequestIndexes: [1] },
      { documentIndex: 1, docRequestIndexes: [0] },
    ])
  })

  test('the document that satisfies a doc request is not reported as not answering it', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        { namespaces: { [mdlNamespace]: { family_name: false } }, requestInfo: unique },
        { namespaces: { [mdlNamespace]: { given_name: false, birth_date: false } }, requestInfo: unique },
      ],
      useCases: [
        { mandatory: true, documentSets: [[0]] },
        { mandatory: false, documentSets: [[1]] },
      ],
    })
    // Document 0 only has birth_date, which satisfies neither doc request; document 1 satisfies the first.
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [await withClaims(['birth_date'], 1), await withClaims(['family_name'], 0)],
      },
      mdocContext
    )

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })
    const checks: Array<VerificationAssessment> = []
    reportDeviceRequestMatch(match, (check) => checks.push(check))

    expect(match.success).toBe(true)
    expect(match.attribution.documents).toStrictEqual([
      { documentIndex: 0, docRequestIndexes: [1] },
      { documentIndex: 1, docRequestIndexes: [0] },
    ])
    expect(checks.filter((check) => check.status !== 'PASSED')).toStrictEqual([])
  })
})

describe('doc requests answered together', () => {
  const unique = DocRequestInfo.create({ uniqueDocSetRequired: true })
  const familyName = { namespaces: { [mdlNamespace]: { family_name: false } }, requestInfo: unique }
  // One document with family_name for the first doc request, one with nothing for the second.
  const respond = async (deviceRequest: DeviceRequest) =>
    Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
          {
            issuerSigned: await createIssuerSigned(),
            docRequestIndex: 1,
            elements: {},
            signature: { signingKey: deviceKey },
          },
        ],
      },
      mdocContext
    )
  const report = (match: DeviceRequestMatchResult) => {
    const checks: Array<VerificationAssessment> = []
    reportDeviceRequestMatch(match, (check) => checks.push(check))
    return checks.filter((check) => check.status === 'FAILED').map(({ check, reason }) => ({ check, reason }))
  }

  test('two doc requests that take one document each are not both satisfied by the one document that satisfies them', async () => {
    const deviceRequest = createDeviceRequest({ docRequests: [familyName, familyName] })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse: await respond(deviceRequest) })

    expect(match.success).toBe(false)
    expect(match.docRequests.map((docRequest) => docRequest.success)).toStrictEqual([true, true])
    expect(report(match)).toStrictEqual([
      {
        check: 'Device response must answer the doc requests it satisfies together',
        reason:
          'Its doc requests are each satisfied, but not together: those with uniqueDocSetRequired cannot each have a document that satisfies them',
      },
    ])
  })

  test('two mandatory use cases that can each be answered, but not together, fail', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [familyName, familyName],
      useCases: [
        { mandatory: true, documentSets: [[0]] },
        { mandatory: true, documentSets: [[1]] },
      ],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse: await respond(deviceRequest) })

    expect(match).toMatchObject({
      success: false,
      useCases: [{ success: true }, { success: true }],
      reason:
        'Every use case it requires can be answered, but not together: the doc requests with uniqueDocSetRequired among them cannot each have a document that satisfies them',
    })
    expect(report(match).map(({ check }) => check)).toStrictEqual([
      'Device response must answer the doc requests it satisfies together',
    ])

    // One of them on its own is answered.
    const optional = createDeviceRequest({
      docRequests: [familyName, familyName],
      useCases: [
        { mandatory: true, documentSets: [[0]] },
        { mandatory: false, documentSets: [[1]] },
      ],
    })
    const answered = Verifier.matchDeviceRequest({ deviceRequest: optional, deviceResponse: await respond(optional) })
    expect(answered.success).toBe(true)
    expect(answered.attribution.useCases).toStrictEqual([{ useCaseIndex: 0, documentSet: [0] }])
  })

  test('a document that may be a partial answer to an unanswered use case is not warned about, whatever the order of the doc requests', async () => {
    const familyName = { namespaces: { [mdlNamespace]: { family_name: false } } }
    const givenName = { namespaces: { [mdlNamespace]: { given_name: false } }, requestInfo: unique }
    for (const familyNameUnique of [true, false]) {
      const alternative = familyNameUnique ? { ...familyName, requestInfo: unique } : familyName
      // The doc request of the optional use case comes second or third.
      for (const [docRequests, useCases] of [
        [
          [{ ...familyName, requestInfo: unique }, alternative, givenName],
          [
            { mandatory: true, documentSets: [[0], [1]] },
            { mandatory: false, documentSets: [[2]] },
          ],
        ],
        [
          [{ ...familyName, requestInfo: unique }, givenName, alternative],
          [
            { mandatory: true, documentSets: [[0], [2]] },
            { mandatory: false, documentSets: [[1]] },
          ],
        ],
      ] as const) {
        const deviceRequest = createDeviceRequest({
          docRequests: [...docRequests],
          useCases: useCases.map((useCase) => ({
            ...useCase,
            documentSets: useCase.documentSets.map((set) => [...set]),
          })),
        })
        const optional = useCases[1].documentSets[0][0]
        // The second document answers the optional use case with everything left out.
        const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
          {
            deviceRequest,
            sessionTranscript,
            documents: [
              { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
              {
                issuerSigned: await createIssuerSigned(),
                docRequestIndex: optional,
                elements: {},
                signature: { signingKey: deviceKey },
              },
            ],
          },
          mdocContext
        )

        const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })
        const checks: Array<VerificationAssessment> = []
        reportDeviceRequestMatch(match, (check) => checks.push(check))

        expect(match.success).toBe(true)
        expect(checks.filter((check) => check.status !== 'PASSED')).toStrictEqual([])
      }
    }
  })

  test('a partial answer to an optional use case that cannot be answered with the mandatory one is not warned about', async () => {
    const both = {
      namespaces: { [mdlNamespace]: { family_name: false, given_name: false } },
      requestInfo: unique,
    }
    const deviceRequest = createDeviceRequest({
      docRequests: [both, both],
      useCases: [
        { mandatory: true, documentSets: [[0]] },
        { mandatory: false, documentSets: [[1]] },
      ],
    })
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
          {
            issuerSigned: await createIssuerSigned(),
            docRequestIndex: 1,
            elements: { [mdlNamespace]: ['given_name'] },
            signature: { signingKey: deviceKey },
          },
        ],
      },
      mdocContext
    )

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })
    const checks: Array<VerificationAssessment> = []
    reportDeviceRequestMatch(match, (check) => checks.push(check))

    // The optional use case can be answered on its own, but not with the mandatory one.
    expect(match).toMatchObject({ success: true, useCases: [{ success: true }, { success: true }] })
    expect(match.attribution.useCases).toStrictEqual([{ useCaseIndex: 0, documentSet: [0] }])
    expect(checks.filter((check) => check.status !== 'PASSED')).toStrictEqual([])
  })
})

describe('a document for several doc requests', () => {
  const respond = async (
    deviceRequest: DeviceRequest,
    document: Partial<DeviceResponseDocumentOptions> & Pick<DeviceResponseDocumentOptions, 'docRequestIndex'>
  ) =>
    Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [{ issuerSigned: await createIssuerSigned(), signature: { signingKey: deviceKey }, ...document }],
      },
      mdocContext
    )

  test('discloses what every doc request it answers asks for', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        { namespaces: { [mdlNamespace]: { family_name: false } } },
        { namespaces: { [mdlNamespace]: { given_name: false } } },
      ],
    })

    const deviceResponse = await respond(deviceRequest, { docRequestIndex: [0, 1] })

    expect(deviceResponse.documents?.[0].issuerSigned.getPrettyClaims(mdlNamespace)).toStrictEqual({
      family_name: 'Doe',
      given_name: 'John',
    })
  })

  test('counts for each of them when one requires a unique document set', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        { namespaces: { [mdlNamespace]: { family_name: false } } },
        {
          namespaces: { [mdlNamespace]: { given_name: false } },
          requestInfo: DocRequestInfo.create({ uniqueDocSetRequired: true }),
        },
      ],
    })

    await expect(
      Holder.createDeviceResponseForDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [
            { issuerSigned: await createIssuerSigned(), docRequestIndex: [0, 1], signature: { signingKey: deviceKey } },
            { issuerSigned: await createIssuerSigned(), docRequestIndex: 1, signature: { signingKey: deviceKey } },
          ],
        },
        mdocContext
      )
    ).rejects.toThrow(
      new UnsatisfiedDeviceRequestError(
        'More than one document answers doc request 1, but it requires a unique document set'
      )
    )
  })

  test('cannot choose an alternative set for an element its doc requests have different alternatives for', async () => {
    const alternatives = (set: Array<[string, string]>) =>
      DocRequestInfo.create({
        alternativeDataElements: [{ requestedElement: [mdlNamespace, 'age_in_years'], alternativeElementSets: [set] }],
      })
    const request = (second: DocRequestInfo | undefined) =>
      createDeviceRequest({
        docRequests: [
          {
            namespaces: { [mdlNamespace]: { age_in_years: false } },
            requestInfo: alternatives([[mdlNamespace, 'birth_date']]),
          },
          { namespaces: { [mdlNamespace]: { age_in_years: false, family_name: false } }, requestInfo: second },
        ],
      })
    const chooseBirthDate = { docRequestIndex: [0, 1], alternatives: { [mdlNamespace]: { age_in_years: 0 } } }

    const same = await respond(request(alternatives([[mdlNamespace, 'birth_date']])), chooseBirthDate)
    expect(same.documents?.[0].issuerSigned.getPrettyClaims(mdlNamespace)).toStrictEqual({
      family_name: 'Doe',
      birth_date: '1990-01-01',
    })

    for (const second of [undefined, alternatives([[mdlNamespace, 'given_name']])]) {
      await expect(respond(request(second), chooseBirthDate)).rejects.toThrow(
        new InvalidElementSelectionError(
          `Alternative set 0 of element 'age_in_years' in namespace '${mdlNamespace}' is selected for disclosure, but doc requests 0, 1 have different alternatives for it. Answer them with separate documents`
        )
      )
    }
    // Without a choice, the credential does not have the element, and none of the sets answers both.
    await expect(respond(request(undefined), { docRequestIndex: [0, 1] })).rejects.toThrow(
      new MissingRequestedElementError(
        `Element 'age_in_years' in namespace '${mdlNamespace}' is not in the credential, and doc requests 0, 1 have different alternatives for it. Answer them with separate documents`
      )
    )
    // Also when the doc request without alternatives for it comes first.
    await expect(respond(request(undefined), { ...chooseBirthDate, docRequestIndex: [1, 0] })).rejects.toThrow(
      new InvalidElementSelectionError(
        `Alternative set 0 of element 'age_in_years' in namespace '${mdlNamespace}' is selected for disclosure, but doc requests 1, 0 have different alternatives for it. Answer them with separate documents`
      )
    )
  })

  test('is attributed by the verifier to every doc request of the answered document sets it may answer', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        { namespaces: { [mdlNamespace]: { family_name: false } } },
        { namespaces: { [mdlNamespace]: { given_name: false } } },
        { docType: photoIdDocType, namespaces: { [mdlNamespace]: { family_name: false } } },
      ],
      useCases: [
        { mandatory: true, documentSets: [[0, 1]] },
        { mandatory: false, documentSets: [[2]] },
      ],
    })

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
          { issuerSigned: await createIssuerSigned(), docRequestIndex: 1, signature: { signingKey: deviceKey } },
        ],
      },
      mdocContext
    )

    // Either document may answer either doc request, with elements left out.
    expect(Verifier.matchDeviceRequest({ deviceRequest, deviceResponse }).attribution).toStrictEqual({
      useCases: [{ useCaseIndex: 0, documentSet: [0, 1] }],
      documents: [
        { documentIndex: 0, docRequestIndexes: [0, 1] },
        { documentIndex: 1, docRequestIndexes: [0, 1] },
      ],
    })
  })

  test('is refused for doc requests of another docType, or none', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        { namespaces: { [mdlNamespace]: { family_name: false } } },
        { docType: photoIdDocType, namespaces: { [mdlNamespace]: { family_name: false } } },
      ],
    })

    await expect(respond(deviceRequest, { docRequestIndex: [0, 1] })).rejects.toThrow(DocTypeMismatchError)
    await expect(respond(deviceRequest, { docRequestIndex: [] })).rejects.toThrow(
      new Error('A document has to answer at least one doc request')
    )
  })
})
