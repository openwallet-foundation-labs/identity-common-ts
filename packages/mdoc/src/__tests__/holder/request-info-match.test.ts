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
  ItemsRequest,
  SessionTranscript,
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

  test('a verifier refuses a document from an issuer the doc request does not name', async () => {
    const deviceRequest = createDeviceRequest({
      docRequests: [
        {
          namespaces: { [mdlNamespace]: { family_name: false } },
          requestInfo: DocRequestInfo.create({ issuerIdentifiers: [hex.decode('00112233')] }),
        },
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
      docRequestsAsAlternatives: true,
      useCases: [{ useCaseIndex: 0, mandatory: true, success: true, documentSet: [1] }],
    })
  })

  test('the first document set that is satisfied is the one to answer', async () => {
    const match = Holder.matchDeviceRequest({
      deviceRequest: mdlOrPhotoId(),
      credentials: [await createIssuerSigned({ docType: photoIdDocType }), await createIssuerSigned()],
    })

    expect(match.useCases?.[0].documentSet).toStrictEqual([0])
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
        { useCaseIndex: 0, mandatory: true, success: false },
        { useCaseIndex: 1, mandatory: false, success: true, documentSet: [0] },
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

    expect(result.deviceRequestMatch).toMatchObject({ success: true, useCases: [{ success: true, documentSet: [0] }] })
    expect(checks.filter((check) => check.status !== 'PASSED')).toStrictEqual([])
    expect(checks.map((check) => check.check)).toContain('Device response must satisfy mandatory use case 0')
  })
})
