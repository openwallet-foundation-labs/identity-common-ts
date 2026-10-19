import { hexEncode } from '@owf/identity-common'
import { parseCertificate } from '@owf/x509'
import type { VerificationCallback } from '../mdoc/check-callback'
import { InvalidDeviceRequestMatchOptionsError } from '../mdoc/errors'
import type { AlternativeDataElementsSet } from '../mdoc/models/alternative-data-elements-set'
import type { DataElementIdentifier } from '../mdoc/models/data-element-identifier'
import type { DataElementValue } from '../mdoc/models/data-element-value'
import type { DeviceNamespaces } from '../mdoc/models/device-namespaces'
import type { DeviceRequest } from '../mdoc/models/device-request'
import type { DeviceResponse } from '../mdoc/models/device-response'
import type { DocType } from '../mdoc/models/doctype'
import type { IntentToRetain } from '../mdoc/models/intent-to-retain'
import { IssuerSigned } from '../mdoc/models/issuer-signed'
import type { IssuerSignedItem } from '../mdoc/models/issuer-signed-item'
import type { KeyAuthorizations } from '../mdoc/models/key-authorizations'
import type { Namespace } from '../mdoc/models/namespace'
import {
  describeAgeOverLimitViolations,
  findAgeOverCandidate,
  findAgeOverLimitViolations,
  findAgeOverRequestLimitViolations,
} from './ageOver'
import { getOwnProperty } from './getOwnProperty'
import { isDeviceSignedElementAuthorized } from './keyAuthorizations'

export type DisclosedElementSource = 'issuerSigned' | 'deviceSigned'

export type DisclosedElement = {
  namespace: Namespace
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
  source: DisclosedElementSource
}

/**
 * How a single requested element is matched. An `ItemsRequest` can express neither that an element
 * is optional nor where it is expected to come from, so the verifier — which built the request —
 * provides it as context to the match.
 */
export type ElementMatchOptions = {
  /**
   * Whether the response may leave this element out without failing the match. An optional element
   * never makes a document fail, but it is still reported per claim. Defaults to `false`.
   */
  optional?: boolean

  /**
   * Where the element may be disclosed from. Device-signed elements are asserted by the mdoc
   * itself and not by the issuer, so an element the issuer is expected to attest to, an
   * `age_over_NN` for instance, must not be answered from `deviceSigned`. Defaults to
   * `'issuerSigned'`.
   *
   * Even if `'deviceSigned'` is allowed, the element must be in the key authorizations of the mdoc.
   */
  source?: DisclosedElementSource | 'any'
}

export type DocRequestMatchOptions = {
  /**
   * Index into `deviceRequest.docRequests` of the doc request these options apply to.
   */
  docRequestIndex: number

  /**
   * Per-element match options, keyed by namespace and element identifier. The element identifier
   * `'*'` applies to every element in the namespace that is not named explicitly, which is how a
   * namespace that is entirely device-signed is described.
   *
   * ```ts
   * {
   *   'org.iso.18013.5.1': { portrait: { optional: true } },
   *   'com.example.device': { '*': { source: 'deviceSigned' } },
   * }
   * ```
   */
  elements?: Record<Namespace, Record<DataElementIdentifier, ElementMatchOptions>>
}

/**
 * Per doc request the elements that are optional or that may be answered from `deviceSigned`. By
 * default every requested element is required and must be issuer-signed.
 */
export type DeviceRequestMatchOptions = {
  /**
   * A doc request can have options at most once.
   */
  docRequests?: Array<DocRequestMatchOptions>

  /**
   * A device request with more than one doc request and no use cases does not say whether it asks
   * for all of them, or for any one of them. ISO/IEC TS 23220-4 7.2.1.3.2 reads it as all of them,
   * which is the default: a single mandatory use case whose document set holds every doc request.
   * Set this to treat them as alternatives instead, one optional use case per doc request, of which
   * at least one has to be satisfied. That is how the iOS DC API presents such a request.
   *
   * A device request that carries use cases (ISO/IEC TS 23220-4 7.2.1.3.4, taken up by the second
   * edition of 18013-5) is matched by them, and this option does not apply. Neither does it to a
   * device request with a single doc request. Defaults to `false`.
   */
  treatAmbiguousMultipleDocRequestsAsAlternatives?: boolean
}

export type ClaimMatchBase = {
  namespace: Namespace
  /**
   * The element identifier as it appears in the `ItemsRequest`.
   */
  elementIdentifier: DataElementIdentifier
  intentToRetain: IntentToRetain
  /**
   * Whether the element was matched as optional, and therefore cannot make the claims fail. Always
   * `false` when matching the credentials of a holder, as the request does not say which elements
   * are optional.
   */
  optional: boolean
}

export type ClaimMatchSuccess = ClaimMatchBase & {
  success: true
  /**
   * The element identifier that is disclosed. Only differs from `elementIdentifier` when an
   * `age_over_NN` request is answered with a different age attestation (18013-5 7.2.5).
   */
  disclosedElementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
  source: DisclosedElementSource
  /**
   * Set when the doc request has alternatives for the element (ISO/IEC TS 23220-4 7.2.1.3.2): every
   * way it can be answered, in order of preference. The element itself comes first when it is
   * there, then each alternative set whose elements all are, in the reader's order, possibly in other
   * namespaces (18013-5 second edition 10.2.4).
   *
   * `disclosedElementIdentifier`, `elementValue` and `source` describe the first element of the first
   * option. That option is an alternative set (it has an `alternativeElementSetIndex`) only when the
   * element itself is not there. A holder discloses an alternative set by choosing it with the
   * `alternatives` of the document it creates, and otherwise the element itself.
   */
  options?: NonEmptyArray<ClaimMatchOption>
}

/**
 * One way to answer a requested element that has alternatives (ISO/IEC TS 23220-4 7.2.1.3.2): the
 * element itself, or every element of one of its alternative sets (18013-5 second edition 10.2.4).
 */
export type ClaimMatchOption = {
  /**
   * Index into the `alternativeElementSets` of the element, when the option is one of them rather
   * than the element itself.
   */
  alternativeElementSetIndex?: number
  elements: NonEmptyArray<DisclosedElement>
}

export type ClaimMatchFailure = ClaimMatchBase & {
  success: false
  /**
   * `'notDisclosed'` — the document did not disclose the element, or the credential cannot: the
   * issuer did not sign it, and either the device key is not authorized for it or no value was
   * provided for it in the device namespaces.
   *
   * `'disallowedSource'` — the document did disclose it, but only from a source the match options
   * do not allow for this element. By default only `issuerSigned` is allowed, so a `deviceSigned`
   * element the verifier did not mark as device-signed fails here rather than counting as a match.
   *
   * `'deviceKeyNotAuthorized'` — the document did disclose it device-signed, from a source the match
   * options allow, but the device key is not authorized for it in the key authorizations of the MSO
   * (18013-5 9.1.3.4).
   */
  failure: 'notDisclosed' | 'disallowedSource' | 'deviceKeyNotAuthorized'
  /**
   * The source the element was disclosed from, when `failure` is `'disallowedSource'` or
   * `'deviceKeyNotAuthorized'`.
   */
  disclosedFrom?: DisclosedElementSource
  reason: string
}

export type ClaimMatch = ClaimMatchSuccess | ClaimMatchFailure

type NonEmptyArray<T> = [T, ...Array<T>]

export type DocTypeMatchSuccess = {
  success: true
  docType: DocType
}

export type DocTypeMatchFailure = {
  success: false
  /**
   * The docType of the document or credential.
   */
  docType: DocType
  reason: string
}

/**
 * Whether a document or credential has the docType the doc request asks for.
 */
export type DocTypeMatchResult = DocTypeMatchSuccess | DocTypeMatchFailure

export type IssuerMatchSuccess = { success: true }
export type IssuerMatchFailure = { success: false; reason: string }

/**
 * Whether a document or credential comes from an issuer the doc request accepts: a certificate in
 * its certificate chain has one of the `issuerIdentifiers` of the `requestInfo` of the doc request
 * as its authority key identifier (ISO/IEC TS 23220-4 7.2.1.3.2, 18013-5 second edition 10.2.4).
 * Only present when the doc request names issuers.
 */
export type IssuerMatchResult = IssuerMatchSuccess | IssuerMatchFailure

/**
 * Every requested element that is not optional is disclosed.
 */
export type ClaimsMatchSuccess = {
  success: true
  /**
   * The requested elements that are disclosed, in request order.
   */
  validClaims: Array<ClaimMatchSuccess>
  /**
   * The optional requested elements that are not disclosed, in request order.
   */
  failedClaims: Array<ClaimMatchFailure & { optional: true }>
}

/**
 * At least one requested element that is not optional is not disclosed.
 */
export type ClaimsMatchFailure = {
  success: false
  /**
   * The requested elements that are disclosed, in request order.
   */
  validClaims: Array<ClaimMatchSuccess>
  /**
   * The requested elements that are not disclosed, in request order. Can contain optional elements.
   */
  failedClaims: NonEmptyArray<ClaimMatchFailure>
}

export type ClaimsMatchResult = ClaimsMatchSuccess | ClaimsMatchFailure

type UnrequestedClaims = {
  /**
   * Elements the document disclosed that the doc request did not ask for. Not a failure by itself
   * — it is the mdoc over-disclosing — but a verifier should not process data it did not request.
   */
  unrequestedClaims: Array<DisclosedElement>
}

export type DocumentClaimsMatchSuccess = ClaimsMatchSuccess & UnrequestedClaims
export type DocumentClaimsMatchFailure = ClaimsMatchFailure & UnrequestedClaims
export type DocumentClaimsMatchResult = DocumentClaimsMatchSuccess | DocumentClaimsMatchFailure

type DocumentMatchBase = {
  /**
   * Index into `deviceResponse.documents` of the document this result is about.
   */
  documentIndex: number
}

export type DocumentMatchSuccess = DocumentMatchBase & {
  success: true
  docType: DocTypeMatchSuccess
  issuer?: IssuerMatchSuccess
  claims: DocumentClaimsMatchSuccess
}

export type DocumentMatchFailure = DocumentMatchBase & {
  success: false
  docType: DocTypeMatchResult
  issuer?: IssuerMatchResult
  claims: DocumentClaimsMatchResult
}

/**
 * Whether a document satisfies a doc request. The `docType` check requires both the docType of the
 * document and the docType of its mobile security object to be the requested docType: the docType
 * outside the MSO is not signed.
 */
export type DocumentMatch = DocumentMatchSuccess | DocumentMatchFailure

type DocRequestMatchBase = {
  /**
   * Index into `deviceRequest.docRequests` of the doc request this result is about.
   */
  docRequestIndex: number
  docType: DocType
  /**
   * The documents that do not satisfy this doc request, in response order. This includes every
   * document of another docType, for which the `docType` check failed.
   */
  failedDocuments: Array<DocumentMatchFailure>
}

export type DocRequestMatchSuccess = DocRequestMatchBase & {
  success: true
  /**
   * The documents that satisfy this doc request, in response order.
   */
  validDocuments: NonEmptyArray<DocumentMatchSuccess>
}

export type DocRequestMatchFailure = DocRequestMatchBase & {
  success: false
  /**
   * Empty, unless the doc request requires a unique document set that the response does not give,
   * see `reason`.
   */
  validDocuments: Array<DocumentMatchSuccess>
  /**
   * Set when the `requestInfo` of the doc request sets `uniqueDocSetRequired` (ISO/IEC TS 23220-4
   * 7.2.1.3.2), and more documents satisfy it than one, plus one for each other doc request of its
   * docType. A response does not say which document answers which doc request, and a document that
   * satisfies this one may answer another of the same docType with elements left out.
   */
  reason?: string
}

export type DocRequestMatch = DocRequestMatchSuccess | DocRequestMatchFailure

/**
 * How a use case is satisfied.
 */
export type UseCaseMatch = {
  /**
   * Index into `useCases` of the use case this result is about, which for use cases of the device
   * request is also their index into `deviceRequestInfo.useCases`.
   */
  useCaseIndex: number
  mandatory: boolean
  /**
   * The purpose hints of the use case, to tell the user what each use case is for (18013-5 second
   * edition 10.2.5). Only use cases of the `deviceRequestInfo` have them.
   */
  purposeHints?: Map<string, number>
  success: boolean
  /**
   * Every document set of the use case, in request order: the doc requests, by index, that answer
   * it together.
   */
  documentSets: Array<Array<number>>
  /**
   * The document sets of `documentSets` whose doc requests are all satisfied, in request order.
   * Empty when none is. A holder answers exactly one of them (ISO/IEC TS 23220-4 7.2.1.4).
   */
  matchingDocumentSets: Array<Array<number>>
}

/**
 * Where the use cases of a match come from.
 *
 * `'deviceRequestInfo'`: the use cases of the `deviceRequestInfo` of the device request (ISO/IEC TS
 * 23220-4 7.2.1.3.4).
 *
 * `'allDocRequests'`: the device request carries none, so every doc request is requested (7.2.1.3.2):
 * a single mandatory use case, whose one document set holds every doc request.
 *
 * `'eachDocRequest'`: the device request carries none, and
 * `treatAmbiguousMultipleDocRequestsAsAlternatives` is set: one optional use case per doc request.
 */
export type UseCasesSource = 'deviceRequestInfo' | 'allDocRequests' | 'eachDocRequest'

export type UseCasesMatch = {
  useCasesSource: UseCasesSource
  /**
   * One entry per use case, in order. The match succeeds when every mandatory use case is satisfied
   * and at least one use case is (18013-5 second edition 10.2.5).
   */
  useCases: Array<UseCaseMatch>
}

type DeviceRequestMatchBase = UseCasesMatch & {
  /**
   * Documents in the response whose docType no doc request asked for.
   */
  unrequestedDocuments: Array<{ documentIndex: number; docType: DocType }>
}

/**
 * Every mandatory use case is satisfied, and at least one use case is.
 */
export type DeviceRequestMatchSuccess = DeviceRequestMatchBase &
  (
    | {
        success: true
        useCasesSource: 'allDocRequests'
        /**
         * One entry per doc request, in request order. All of them are successful.
         */
        docRequests: Array<DocRequestMatchSuccess>
      }
    | {
        success: true
        useCasesSource: 'deviceRequestInfo' | 'eachDocRequest'
        /**
         * One entry per doc request, in request order.
         */
        docRequests: Array<DocRequestMatch>
      }
  )

export type DeviceRequestMatchFailure = DeviceRequestMatchBase & {
  success: false
  /**
   * One entry per doc request, in request order.
   */
  docRequests: Array<DocRequestMatch>
}

export type DeviceRequestMatchResult = DeviceRequestMatchSuccess | DeviceRequestMatchFailure

type CredentialMatchBase = {
  /**
   * Index into `credentials` of the credential this result is about.
   */
  credentialIndex: number
}

export type CredentialMatchSuccess = CredentialMatchBase & {
  success: true
  docType: DocTypeMatchSuccess
  issuer?: IssuerMatchSuccess
  claims: ClaimsMatchSuccess
}

export type CredentialMatchFailure = CredentialMatchBase & {
  success: false
  docType: DocTypeMatchResult
  issuer?: IssuerMatchResult
  claims: ClaimsMatchResult
}

/**
 * Whether a credential can satisfy a doc request. The `docType` check requires the docType of the
 * mobile security object of the credential to be the requested docType.
 */
export type CredentialMatch = CredentialMatchSuccess | CredentialMatchFailure

type HolderDocRequestMatchBase = {
  /**
   * Index into `deviceRequest.docRequests` of the doc request this result is about.
   */
  docRequestIndex: number
  docType: DocType
  /**
   * The credentials that do not satisfy this doc request, in the order they were provided. This
   * includes every credential of another docType, for which the `docType` check failed. Empty when
   * the doc request is invalid, as credentials are then not matched.
   */
  failedCredentials: Array<CredentialMatchFailure>
}

export type HolderDocRequestMatchSuccess = HolderDocRequestMatchBase & {
  success: true
  /**
   * The credentials that satisfy this doc request, in the order they were provided.
   */
  validCredentials: NonEmptyArray<CredentialMatchSuccess>
}

/**
 * Why a doc request cannot be answered by any credential.
 *
 * `'ageOverLimitExceeded'` — the doc request asks for more than two `age_over_NN` elements in a
 * namespace, which 18013-5 7.2.5 forbids a reader to do, as together they narrow down the age of
 * the holder.
 */
export type InvalidDocRequest = {
  failure: 'ageOverLimitExceeded'
  reason: string
}

export type HolderDocRequestMatchFailure = HolderDocRequestMatchBase & {
  success: false
  validCredentials: []
  /**
   * Set when the doc request itself is invalid. No credential is then matched against it, so
   * `failedCredentials` is empty.
   */
  invalidDocRequest?: InvalidDocRequest
}

export type HolderDocRequestMatch = HolderDocRequestMatchSuccess | HolderDocRequestMatchFailure

/**
 * Every mandatory use case can be satisfied, and at least one use case can.
 */
export type HolderDeviceRequestMatchSuccess = UseCasesMatch &
  (
    | {
        success: true
        useCasesSource: 'allDocRequests'
        /**
         * One entry per doc request, in request order. All of them are successful.
         */
        docRequests: Array<HolderDocRequestMatchSuccess>
      }
    | {
        success: true
        useCasesSource: 'deviceRequestInfo' | 'eachDocRequest'
        /**
         * One entry per doc request, in request order.
         */
        docRequests: Array<HolderDocRequestMatch>
      }
  )

export type HolderDeviceRequestMatchFailure = UseCasesMatch & {
  success: false
  /**
   * One entry per doc request, in request order.
   */
  docRequests: Array<HolderDocRequestMatch>
}

export type HolderDeviceRequestMatchResult = HolderDeviceRequestMatchSuccess | HolderDeviceRequestMatchFailure

/**
 * A credential of the holder, with the values the holder can disclose device-signed for it.
 */
export type HolderCredential = {
  issuerSigned: IssuerSigned
  /**
   * The values the holder can disclose device-signed with this credential. A requested element the
   * issuer did not sign only matches when its value is here and the device key is authorized for
   * it, the same as when creating the response.
   */
  deviceNamespaces?: DeviceNamespaces
}

/**
 * Match a `DeviceResponse` against the `DeviceRequest` it answers (verifier side).
 *
 * The ISO mdoc DC API protocol (`org-iso-mdoc`) has no query language such as DCQL that describes
 * which claims a response has to contain, so this walks the device request itself and reports, per
 * doc request, per document and per check whether the response satisfies it.
 *
 * An element only counts as disclosed when it comes from `issuerSigned`, as `deviceSigned` elements
 * are asserted by the mdoc itself rather than by the issuer. Pass `matchOptions` to mark elements
 * that are optional or that are expected to be device-signed.
 *
 * The doc requests are matched by use case: those of the device request (ISO/IEC TS 23220-4
 * 7.2.1.3.4) when it carries them, and otherwise every doc request as one mandatory use case, or each
 * doc request as an optional one when `treatAmbiguousMultipleDocRequestsAsAlternatives` is set in
 * `matchOptions`. The match succeeds when every mandatory use case is satisfied and at least one is.
 *
 * The `requestInfo` of a doc request is applied too: a document of an issuer it does not name
 * fails, an alternative set it allows answers a requested element, and its elements count as
 * requested rather than over-disclosed, and with
 * `uniqueDocSetRequired` the doc request fails when more documents satisfy it than one, plus one for
 * each other doc request of its docType, which they may answer instead.
 *
 * Shares its matching with {@link matchCredentialsToDeviceRequest}, which matches like a verifier
 * that accepts every element from `'any'` source.
 *
 * This is purely a structural comparison — it does not verify issuer auth, device auth or the
 * digests of the disclosed elements. Use it alongside `DeviceResponse.verify`, which runs it as
 * part of verification when a `deviceRequest` is passed.
 */
export const matchDeviceRequest = (options: {
  deviceRequest: DeviceRequest
  deviceResponse: DeviceResponse
  matchOptions?: DeviceRequestMatchOptions
  /**
   * Per document, in response order, its certificate chain as validated against the trusted
   * certificates, leaf first. The `issuerIdentifiers` of a doc request are matched against it, and
   * a document without one does not satisfy a doc request that names issuers. The x5chain is not
   * used: it is in the unprotected header of the IssuerAuth, so a holder can add the certificate of
   * any issuer to it. `Verifier.verifyDeviceResponse` passes the chains it validates.
   */
  issuerCertificateChains?: Array<Array<Uint8Array> | undefined>
}): DeviceRequestMatchResult => {
  const { deviceRequest, deviceResponse, matchOptions } = options
  const docRequestOptions = indexDocRequestOptions(deviceRequest, matchOptions)

  // Every access to the mobile security object decodes it, so decode it once per document.
  const documents = (deviceResponse.documents ?? []).map((document) => ({
    document,
    mobileSecurityObject: document.issuerSigned.issuerAuth.mobileSecurityObject,
  }))

  const matches = deviceRequest.docRequests.map((docRequest, docRequestIndex) => {
    const { docType, namespaces, requestInfo } = docRequest.itemsRequest
    const elements = docRequestOptions.get(docRequestIndex)?.elements

    const documentMatches = documents.map(({ document, mobileSecurityObject }, documentIndex): DocumentMatch => {
      const mobileSecurityObjectDocType = mobileSecurityObject.docType
      const docTypeResult: DocTypeMatchResult =
        document.docType !== docType
          ? {
              success: false,
              docType: document.docType,
              reason: `Document has docType '${document.docType}', but docType '${docType}' was requested`,
            }
          : mobileSecurityObjectDocType !== docType
            ? {
                success: false,
                docType: document.docType,
                reason: `Document has docType '${docType}', but the mobile security object has docType '${mobileSecurityObjectDocType}'`,
              }
            : { success: true, docType }

      const issuerResult = matchIssuer(
        requestInfo?.issuerIdentifiers,
        options.issuerCertificateChains?.[documentIndex],
        'validated certificate chain'
      )

      const { claims, unusedElements } = matchElements({
        mode: 'verifier',
        namespaces,
        elements,
        issuerSigned: document.issuerSigned,
        keyAuthorizations: mobileSecurityObject.deviceKeyInfo.keyAuthorizations,
        deviceNamespaces: document.deviceSigned.deviceNamespaces,
        alternatives: requestInfo?.alternativeDataElements,
      })
      const claimsResult: DocumentClaimsMatchResult = {
        ...toClaimsMatchResult(claims),
        unrequestedClaims: unusedElements,
      }

      const issuer = issuerResult ? { issuer: issuerResult } : {}
      return docTypeResult.success && claimsResult.success && issuerResult?.success !== false
        ? {
            documentIndex,
            success: true,
            docType: docTypeResult,
            ...(issuer as { issuer?: IssuerMatchSuccess }),
            claims: claimsResult,
          }
        : { documentIndex, success: false, docType: docTypeResult, ...issuer, claims: claimsResult }
    })

    return {
      docRequestIndex,
      docType,
      uniqueDocSetRequired: requestInfo?.uniqueDocSetRequired ?? false,
      validDocuments: documentMatches.filter((documentMatch) => documentMatch.success),
      failedDocuments: documentMatches.filter((documentMatch) => !documentMatch.success),
    }
  })

  const docRequests = matches.map(({ uniqueDocSetRequired, ...match }): DocRequestMatch => {
    const { docRequestIndex, docType, validDocuments, failedDocuments } = match

    // A response does not say which document answers which doc request. A document that satisfies
    // this doc request may answer another one of the same docType, possibly with elements left out,
    // so only the documents that the other doc requests of its docType cannot account for count.
    const otherDocRequests = matches.filter(
      (other) => other.docRequestIndex !== docRequestIndex && other.docType === docType
    ).length
    if (uniqueDocSetRequired && validDocuments.length - otherDocRequests > 1) {
      const documentIndexes = validDocuments.map((document) => document.documentIndex).join(', ')
      return {
        docRequestIndex,
        docType,
        success: false,
        validDocuments,
        failedDocuments,
        reason:
          otherDocRequests === 0
            ? `Documents ${documentIndexes} satisfy doc request ${docRequestIndex}, but it requires a unique document set`
            : `Documents ${documentIndexes} satisfy doc request ${docRequestIndex}, but it requires a unique document set, and the ${otherDocRequests} other doc request(s) of docType '${docType}' can take at most ${otherDocRequests} of them`,
      }
    }

    return isNonEmptyArray(validDocuments)
      ? { docRequestIndex, docType, success: true, validDocuments, failedDocuments }
      : { docRequestIndex, docType, success: false, validDocuments: [], failedDocuments }
  })

  const requestedDocTypes = new Set(deviceRequest.docRequests.map((docRequest) => docRequest.itemsRequest.docType))
  const unrequestedDocuments = documents.flatMap(({ document }, documentIndex) =>
    requestedDocTypes.has(document.docType) ? [] : [{ documentIndex, docType: document.docType }]
  )

  const useCases = matchUseCases(
    resolveUseCases(deviceRequest, matchOptions?.treatAmbiguousMultipleDocRequestsAsAlternatives),
    docRequests
  )
  if (!useCases.success) return { success: false, ...useCases.match, docRequests, unrequestedDocuments }
  if (useCases.match.useCasesSource !== 'allDocRequests') {
    return {
      success: true,
      useCasesSource: useCases.match.useCasesSource,
      useCases: useCases.match.useCases,
      docRequests,
      unrequestedDocuments,
    }
  }
  // A single use case holding every doc request is only satisfied when all of them are.
  return {
    success: true,
    useCasesSource: 'allDocRequests',
    useCases: useCases.match.useCases,
    docRequests: docRequests.filter(isSuccess),
    unrequestedDocuments,
  }
}

/**
 * Match the credentials of a holder against a `DeviceRequest` (holder side), to select which
 * credentials can answer which doc request.
 *
 * Reports per doc request, per credential and per check whether the credential satisfies the doc
 * request, so a holder can show which credentials match, and for a credential of the right docType
 * which requested elements it is missing. Every credential is matched against every doc request, and
 * is referred to by its index in `credentials`.
 *
 * A requested element is disclosed issuer-signed when the issuer signed it (or, for an
 * `age_over_NN` request, the age attestation 18013-5 7.2.5 allows in its place). Otherwise it is
 * disclosed device-signed when the credential comes with a value for exactly that element in its
 * `deviceNamespaces`, and the device key is authorized for it in the key authorizations of the MSO.
 *
 * `DeviceResponse.createWithDeviceRequest` selects the elements to disclose the same way, so a
 * credential that matches can answer the doc request with the same `deviceNamespaces`. The request
 * does not say which elements are optional, so every requested element is required.
 *
 * A doc request that asks for more than two `age_over_NN` elements in a namespace (18013-5 7.2.5)
 * is not matched against any credential, and fails with `invalidDocRequest`.
 *
 * The doc requests are matched by use case, the same way as {@link matchDeviceRequest} does, and each
 * use case lists the document sets the credentials can answer (`matchingDocumentSets`), of which
 * the holder picks one.
 *
 * The `requestInfo` of a doc request is applied too: a credential of an issuer it does not name
 * fails, and a requested element is answered by one of its alternative sets when the credential
 * has one. The claims list every option, of which the holder can pick another than the first.
 *
 * Shares its matching with {@link matchDeviceRequest}: a credential matches like a verifier that
 * accepts every element from `'any'` source would match the response. A verifier only accepts
 * issuer-signed elements by default, so a device-signed element only satisfies it when its match
 * options allow `deviceSigned` for it.
 */
export const matchCredentialsToDeviceRequest = (options: {
  deviceRequest: DeviceRequest
  credentials: Array<IssuerSigned | HolderCredential>
  /**
   * See `DeviceRequestMatchOptions.treatAmbiguousMultipleDocRequestsAsAlternatives`. Defaults to
   * `false`.
   */
  treatAmbiguousMultipleDocRequestsAsAlternatives?: boolean
}): HolderDeviceRequestMatchResult => {
  const { deviceRequest } = options
  const credentials = options.credentials.map((credential) => {
    const { issuerSigned, deviceNamespaces }: HolderCredential =
      credential instanceof IssuerSigned ? { issuerSigned: credential } : credential

    // Every access to the mobile security object decodes it, so decode it once per credential.
    return { issuerSigned, deviceNamespaces, mobileSecurityObject: issuerSigned.issuerAuth.mobileSecurityObject }
  })

  const docRequests = deviceRequest.docRequests.map((docRequest, docRequestIndex): HolderDocRequestMatch => {
    const { docType, namespaces, requestInfo } = docRequest.itemsRequest

    const ageOverLimitViolations = findAgeOverRequestLimitViolations(namespaces)
    if (ageOverLimitViolations.length > 0) {
      return {
        docRequestIndex,
        docType,
        success: false,
        validCredentials: [],
        failedCredentials: [],
        invalidDocRequest: {
          failure: 'ageOverLimitExceeded',
          reason: `Doc request ${docRequestIndex} requests ${describeAgeOverLimitViolations(ageOverLimitViolations)}, but at most two age_over_NN elements may be requested per namespace`,
        },
      }
    }

    const credentialMatches = credentials.map(
      ({ issuerSigned, deviceNamespaces, mobileSecurityObject }, credentialIndex): CredentialMatch => {
        const credentialDocType = mobileSecurityObject.docType
        const docTypeResult: DocTypeMatchResult =
          credentialDocType === docType
            ? { success: true, docType }
            : {
                success: false,
                docType: credentialDocType,
                reason: `Credential has docType '${credentialDocType}', but docType '${docType}' was requested`,
              }

        const issuerResult = matchIssuer(
          requestInfo?.issuerIdentifiers,
          issuerAuthCertificateChain(issuerSigned),
          'x5chain of the IssuerAuth'
        )

        const claimsResult = toClaimsMatchResult(
          matchElements({
            mode: 'holder',
            namespaces,
            issuerSigned,
            keyAuthorizations: mobileSecurityObject.deviceKeyInfo.keyAuthorizations,
            deviceNamespaces,
            alternatives: requestInfo?.alternativeDataElements,
          }).claims
        )

        const issuer = issuerResult ? { issuer: issuerResult } : {}
        return docTypeResult.success && claimsResult.success && issuerResult?.success !== false
          ? {
              credentialIndex,
              success: true,
              docType: docTypeResult,
              ...(issuer as { issuer?: IssuerMatchSuccess }),
              claims: claimsResult,
            }
          : { credentialIndex, success: false, docType: docTypeResult, ...issuer, claims: claimsResult }
      }
    )

    const validCredentials = credentialMatches.filter((credentialMatch) => credentialMatch.success)
    const failedCredentials = credentialMatches.filter((credentialMatch) => !credentialMatch.success)

    return isNonEmptyArray(validCredentials)
      ? { docRequestIndex, docType, success: true, validCredentials, failedCredentials }
      : { docRequestIndex, docType, success: false, validCredentials: [], failedCredentials }
  })

  const useCases = matchUseCases(
    resolveUseCases(deviceRequest, options.treatAmbiguousMultipleDocRequestsAsAlternatives),
    docRequests
  )
  if (!useCases.success) return { success: false, ...useCases.match, docRequests }
  if (useCases.match.useCasesSource !== 'allDocRequests') {
    return {
      success: true,
      useCasesSource: useCases.match.useCasesSource,
      useCases: useCases.match.useCases,
      docRequests,
    }
  }
  // A single use case holding every doc request is only satisfied when all of them are.
  return {
    success: true,
    useCasesSource: 'allDocRequests',
    useCases: useCases.match.useCases,
    docRequests: docRequests.filter(isSuccess),
  }
}

type ResolvedUseCases = {
  useCasesSource: UseCasesSource
  useCases: Array<{ mandatory: boolean; purposeHints?: Map<string, number>; documentSets: Array<Array<number>> }>
}

/**
 * The use cases to match the device request by: its own (ISO/IEC TS 23220-4 7.2.1.3.4), and
 * otherwise every doc request as one mandatory use case (7.2.1.3.2), or with
 * `treatAmbiguousMultipleDocRequestsAsAlternatives` each doc request as an optional use case. A
 * single doc request is not ambiguous, so it always is a mandatory use case of its own.
 */
const resolveUseCases = (
  deviceRequest: DeviceRequest,
  treatAmbiguousMultipleDocRequestsAsAlternatives = false
): ResolvedUseCases => {
  const useCases = deviceRequest.deviceRequestInfo?.useCases
  if (useCases) {
    return {
      useCasesSource: 'deviceRequestInfo',
      useCases: useCases.map(({ mandatory, purposeHints, documentSets }) => ({
        mandatory,
        ...(purposeHints ? { purposeHints } : {}),
        documentSets,
      })),
    }
  }

  const docRequestIndexes = deviceRequest.docRequests.map((_, docRequestIndex) => docRequestIndex)
  if (treatAmbiguousMultipleDocRequestsAsAlternatives && docRequestIndexes.length > 1) {
    return {
      useCasesSource: 'eachDocRequest',
      useCases: docRequestIndexes.map((docRequestIndex) => ({ mandatory: false, documentSets: [[docRequestIndex]] })),
    }
  }

  return { useCasesSource: 'allDocRequests', useCases: [{ mandatory: true, documentSets: [docRequestIndexes] }] }
}

/**
 * Per use case the document sets whose doc requests are all satisfied, and whether the device
 * request is: every mandatory use case and at least one use case has to be (18013-5 second edition
 * 10.2.5).
 */
const matchUseCases = ({ useCasesSource, useCases }: ResolvedUseCases, docRequests: Array<{ success: boolean }>) => {
  const matches = useCases.map(({ mandatory, purposeHints, documentSets }, useCaseIndex): UseCaseMatch => {
    const satisfied = documentSets.filter((set) => set.every((index) => docRequests[index]?.success === true))
    return {
      useCaseIndex,
      mandatory,
      ...(purposeHints ? { purposeHints } : {}),
      success: satisfied.length > 0,
      documentSets,
      matchingDocumentSets: satisfied,
    }
  })

  return {
    match: { useCasesSource, useCases: matches },
    success:
      matches.every((useCase) => !useCase.mandatory || useCase.success) && matches.some((useCase) => useCase.success),
  }
}

/**
 * Whether a document or credential comes from one of `issuerIdentifiers`; undefined when the doc
 * request names no issuer. Matched against the authority key identifiers of `certificateChain`:
 * for a verifier the chain it validated, as the x5chain is in the unprotected header of the
 * IssuerAuth, and for a holder the x5chain of its own credential. Without a chain, it fails.
 *
 * @internal
 */
export const matchIssuer = (
  issuerIdentifiers: Array<Uint8Array> | undefined,
  certificateChain: Array<Uint8Array> | undefined,
  chainName: 'validated certificate chain' | 'x5chain of the IssuerAuth'
): IssuerMatchResult | undefined => {
  if (!issuerIdentifiers) return undefined

  const accepted = `the ${issuerIdentifiers.length} issuer identifier(s) the doc request accepts`
  if (!certificateChain) {
    return { success: false, reason: `The document has no ${chainName} to match ${accepted} against` }
  }

  const keyIdentifiers = certificateChain.flatMap((certificate) => {
    try {
      return parseCertificate(certificate).authorityKeyIdentifier ?? []
    } catch {
      // A certificate that does not parse has no key identifier to match.
      return []
    }
  })

  return issuerIdentifiers.some((identifier) => keyIdentifiers.includes(hexEncode(identifier)))
    ? { success: true }
    : {
        success: false,
        reason: `No certificate in the ${chainName} has one of ${accepted} as its authority key identifier`,
      }
}

/**
 * The x5chain of the IssuerAuth of a credential, which a holder matches issuers against; undefined
 * when it cannot be read.
 *
 * @internal
 */
export const issuerAuthCertificateChain = (issuerSigned: IssuerSigned) => {
  try {
    return issuerSigned.issuerAuth.certificateChain
  } catch {
    return undefined
  }
}

type ElementCandidate = DisclosedElement & {
  /**
   * The issuer-signed item the element comes from, so a holder can disclose it as is.
   */
  issuerSignedItem?: IssuerSignedItem
}

/**
 * @internal
 */
export type ElementMatch =
  | {
      claim: ClaimMatchSuccess
      /**
       * The first element of the first option, see `claim.options`.
       */
      element: ElementCandidate
      /**
       * Every option, as `claim.options` lists them, when the element has alternatives.
       */
      options?: NonEmptyArray<ElementOption>
    }
  | { claim: ClaimMatchFailure; element?: undefined; options?: undefined }

/**
 * @internal
 */
export type ElementOption = { alternativeElementSetIndex?: number; elements: NonEmptyArray<ElementCandidate> }

const toDisclosedElement = ({ issuerSignedItem: _, ...element }: ElementCandidate): DisclosedElement => element

const groupByNamespace = (elements: Array<DisclosedElement>) => {
  const namespaces = new Map<Namespace, Array<DataElementIdentifier>>()
  for (const { namespace, elementIdentifier } of elements) {
    namespaces.set(namespace, [...(namespaces.get(namespace) ?? []), elementIdentifier])
  }
  return namespaces
}

/**
 * Match the requested elements of a single doc request against a single document or credential.
 * Shared by the verifier and the holder side.
 *
 * - `verifier` matches the elements a document disclosed, from the source the `elements` options
 *   allow (by default `issuerSigned`).
 * - `holder` matches the elements a credential can disclose: issuer-signed when the issuer signed
 *   it, and otherwise device-signed when `deviceNamespaces` has a value for exactly that element.
 *   Device-signed values are provided by the holder itself, so an `age_over_NN` request is not
 *   answered with a device-signed value for another age.
 *
 * Either way a device-signed element only answers a request when the device key is authorized for
 * it (18013-5 9.1.3.4).
 *
 * @internal
 */
export const matchElements = (options: {
  mode: 'holder' | 'verifier'
  namespaces: Map<Namespace, Map<DataElementIdentifier, IntentToRetain>>
  elements?: Record<Namespace, Record<DataElementIdentifier, ElementMatchOptions>>
  issuerSigned: IssuerSigned
  /**
   * The key authorizations in the mobile security object of `issuerSigned`, passed in so that the
   * caller decodes the mobile security object only once.
   */
  keyAuthorizations: KeyAuthorizations | undefined
  deviceNamespaces?: DeviceNamespaces
  /**
   * The alternative data elements of the `requestInfo` of the doc request (ISO/IEC TS 23220-4
   * 7.2.1.3.2). Each alternative set whose elements all are there (18013-5 second edition 10.2.4),
   * each found the way the requested element would be, is an option to answer the requested element,
   * after the element itself. The first option answers it. For a holder, an alternative set that
   * would make the response disclose more than two age_over_NN elements in a namespace is not an
   * option.
   */
  alternatives?: Array<AlternativeDataElementsSet>
}): { claims: Array<ElementMatch>; unusedElements: Array<DisclosedElement> } => {
  const { mode, namespaces, keyAuthorizations } = options

  const available = collectElements(options.issuerSigned, options.deviceNamespaces)

  const inNamespace = (namespace: Namespace, source: DisclosedElementSource) =>
    available.filter((element) => element.namespace === namespace && element.source === source)
  const authorizedDeviceSigned = (namespace: Namespace) =>
    inNamespace(namespace, 'deviceSigned').filter((element) =>
      isDeviceSignedElementAuthorized(keyAuthorizations, element)
    )

  /**
   * The element that answers a request for `elementIdentifier` in `namespace`: for a holder
   * issuer-signed, else device-signed when authorized and given for exactly that element; for a
   * verifier from the source its options allow. The same rules as for a requested element.
   */
  const lookup = (namespace: Namespace, elementIdentifier: DataElementIdentifier): ElementCandidate | undefined => {
    if (mode === 'holder') {
      return (
        findElement(elementIdentifier, inNamespace(namespace, 'issuerSigned')) ??
        authorizedDeviceSigned(namespace).find((candidate) => candidate.elementIdentifier === elementIdentifier)
      )
    }
    const namespaceOptions = getOwnProperty(options.elements, namespace)
    const { source = 'issuerSigned' } =
      getOwnProperty(namespaceOptions, elementIdentifier) ?? getOwnProperty(namespaceOptions, '*') ?? {}
    return source === 'deviceSigned'
      ? findElement(elementIdentifier, authorizedDeviceSigned(namespace))
      : (findElement(elementIdentifier, inNamespace(namespace, 'issuerSigned')) ??
          (source === 'any' ? findElement(elementIdentifier, authorizedDeviceSigned(namespace)) : undefined))
  }

  /**
   * Every alternative set of the requested element whose elements all are there, in the reader's
   * order; undefined when the doc request has no alternatives for the element.
   */
  const findAlternatives = (namespace: Namespace, elementIdentifier: DataElementIdentifier) => {
    const alternative = options.alternatives?.find(
      ({ requestedElement: [requestedNamespace, requestedIdentifier] }) =>
        requestedNamespace === namespace && requestedIdentifier === elementIdentifier
    )
    if (!alternative) return undefined

    return alternative.alternativeElementSets.flatMap((set, alternativeElementSetIndex): Array<ElementOption> => {
      const elements = set.map(([alternativeNamespace, alternativeIdentifier]) =>
        lookup(alternativeNamespace, alternativeIdentifier)
      )
      return elements.every((element) => element !== undefined) && isNonEmptyArray(elements)
        ? [{ alternativeElementSetIndex, elements }]
        : []
    })
  }

  /** The options to answer a requested element: itself when it is there, then its alternatives. */
  const optionsFor = (
    namespace: Namespace,
    elementIdentifier: DataElementIdentifier,
    element: ElementCandidate | undefined
  ) => {
    const alternatives = findAlternatives(namespace, elementIdentifier)
    const elementOptions: Array<ElementOption> = [
      ...(element ? [{ elements: [element] as NonEmptyArray<ElementCandidate> }] : []),
      ...(alternatives ?? []),
    ]
    return {
      options: isNonEmptyArray(elementOptions) ? elementOptions : undefined,
      hasAlternatives: alternatives !== undefined,
    }
  }

  const claims: Array<ElementMatch> = []
  const usedElements = new Set<DisclosedElement>()
  // Holder claims are only settled once every requested element is looked up, see below.
  const holderClaims: Array<{
    claim: ClaimMatchBase
    element: ElementCandidate | undefined
    elementOptions: Array<ElementOption> | undefined
    hasAlternatives: boolean
  }> = []

  /**
   * The claim is answered by the first option. `listOptions` is set when the element has
   * alternatives, so that every option is reported.
   */
  const success = (claim: ClaimMatchBase, elementOptions: NonEmptyArray<ElementOption>, listOptions: boolean) => {
    const [first] = elementOptions
    for (const element of first.elements) usedElements.add(element)
    const [element] = first.elements

    claims.push({
      element,
      ...(listOptions ? { options: elementOptions } : {}),
      claim: {
        ...claim,
        success: true,
        disclosedElementIdentifier: element.elementIdentifier,
        elementValue: element.elementValue,
        source: element.source,
        ...(listOptions
          ? {
              options: elementOptions.map(({ alternativeElementSetIndex, elements }) => ({
                ...(alternativeElementSetIndex === undefined ? {} : { alternativeElementSetIndex }),
                elements: elements.map(toDisclosedElement) as NonEmptyArray<DisclosedElement>,
              })) as NonEmptyArray<ClaimMatchOption>,
            }
          : {}),
      },
    })
  }

  const failure = (
    claim: ClaimMatchBase,
    failure: Pick<ClaimMatchFailure, 'failure' | 'disclosedFrom' | 'reason'>,
    // The elements the document disclosed for the claim, so they are not also reported as unrequested.
    ...disclosed: Array<ElementCandidate | undefined>
  ) => {
    for (const element of disclosed) if (element) usedElements.add(element)
    claims.push({ claim: { ...claim, success: false, ...failure } })
  }

  for (const [namespace, requestedElements] of namespaces) {
    const issuerSignedInNamespace = available.filter(
      (element) => element.namespace === namespace && element.source === 'issuerSigned'
    )
    const deviceSignedInNamespace = available.filter(
      (element) => element.namespace === namespace && element.source === 'deviceSigned'
    )
    // 18013-5 9.1.3.4: device-signed elements only answer a request when the device key is
    // authorized for them.
    const authorizedDeviceSignedInNamespace = deviceSignedInNamespace.filter((element) =>
      isDeviceSignedElementAuthorized(keyAuthorizations, element)
    )
    const namespaceOptions = getOwnProperty(options.elements, namespace)

    for (const [elementIdentifier, intentToRetain] of requestedElements) {
      if (mode === 'holder') {
        const claim = { namespace, elementIdentifier, intentToRetain, optional: false }

        const element =
          findElement(elementIdentifier, issuerSignedInNamespace) ??
          authorizedDeviceSignedInNamespace.find((candidate) => candidate.elementIdentifier === elementIdentifier)
        const { options: elementOptions, hasAlternatives } = optionsFor(namespace, elementIdentifier, element)
        holderClaims.push({ claim, element, elementOptions, hasAlternatives })
        continue
      }

      const { optional = false, source = 'issuerSigned' } =
        getOwnProperty(namespaceOptions, elementIdentifier) ?? getOwnProperty(namespaceOptions, '*') ?? {}
      const claim = { namespace, elementIdentifier, intentToRetain, optional }

      // The source is applied before the element is picked, so that an `age_over_NN` request is not
      // answered by a device-signed attestation while an issuer-signed one is also present.
      const element =
        source === 'deviceSigned'
          ? findElement(elementIdentifier, authorizedDeviceSignedInNamespace)
          : (findElement(elementIdentifier, issuerSignedInNamespace) ??
            (source === 'any' ? findElement(elementIdentifier, authorizedDeviceSignedInNamespace) : undefined))

      // ISO/IEC TS 23220-4 7.2.1.3.2: an alternative set the request allows answers it too, when every
      // element of it is there (18013-5 second edition 10.2.4).
      const { options: elementOptions, hasAlternatives } = optionsFor(namespace, elementIdentifier, element)
      if (elementOptions) {
        success(claim, elementOptions, hasAlternatives)
        continue
      }

      // The element may still be there, just not in a way this verifier accepts for it — report
      // that rather than letting it pass or reporting it as absent. Both are marked as used, as the
      // doc request did ask for the element.
      //
      // Disclosed from a source that is not allowed:
      const disallowed =
        source === 'any'
          ? undefined
          : findElement(
              elementIdentifier,
              source === 'issuerSigned' ? deviceSignedInNamespace : issuerSignedInNamespace
            )
      // Disclosed device-signed from an allowed source, but every authorized element was already
      // tried above:
      const unauthorized =
        source === 'issuerSigned' ? undefined : findElement(elementIdentifier, deviceSignedInNamespace)

      // The unauthorized element is the one disclosed from the allowed source, so it is the failure
      // to report when both are there.
      if (unauthorized) {
        failure(
          claim,
          {
            failure: 'deviceKeyNotAuthorized',
            disclosedFrom: 'deviceSigned',
            reason: `Element '${unauthorized.elementIdentifier}' in namespace '${namespace}' was disclosed through deviceSigned, but the device key is not authorized for it in the mobile security object`,
          },
          unauthorized,
          disallowed
        )
        continue
      }

      if (disallowed) {
        failure(
          claim,
          {
            failure: 'disallowedSource',
            disclosedFrom: disallowed.source,
            reason: `Element '${disallowed.elementIdentifier}' in namespace '${namespace}' was disclosed through ${disallowed.source}, but must be disclosed through ${source}`,
          },
          disallowed
        )
        continue
      }

      failure(claim, {
        failure: 'notDisclosed',
        reason: `Element '${elementIdentifier}' in namespace '${namespace}' was not disclosed`,
      })
    }
  }

  // 18013-5 7.2.5: at most two age_over_NN elements are disclosed per namespace. The requested
  // elements the credential has are disclosed by default, so an alternative set is only offered when,
  // disclosed with those of the other claims, it keeps every namespace within two.
  for (const [claimIndex, { claim, element, elementOptions, hasAlternatives }] of holderClaims.entries()) {
    const others = holderClaims.flatMap((other, otherIndex) =>
      otherIndex !== claimIndex && other.element ? [other.element] : []
    )
    const options = elementOptions?.filter(
      (option) =>
        option.alternativeElementSetIndex === undefined ||
        findAgeOverLimitViolations(groupByNamespace([...others, ...option.elements])).length === 0
    )
    if (options && isNonEmptyArray(options)) {
      success(claim, options, hasAlternatives)
      continue
    }

    const { namespace, elementIdentifier } = claim
    failure(claim, {
      failure: 'notDisclosed',
      reason:
        elementOptions && !element
          ? `Element '${elementIdentifier}' in namespace '${namespace}' is not in the credential, and each of its alternative sets the credential has would disclose more than two age_over_NN elements in a namespace`
          : isDeviceSignedElementAuthorized(keyAuthorizations, { namespace, elementIdentifier })
            ? `Element '${elementIdentifier}' in namespace '${namespace}' is not issuer-signed in the credential, so it has to be disclosed device-signed, but no value was provided for it in the device namespaces`
            : `Element '${elementIdentifier}' in namespace '${namespace}' is not issuer-signed in the credential, and the device key is not authorized to sign it`,
    })
  }

  // An element of an alternative set of a requested element is requested too, whether or not it
  // answers it, so disclosing it is not over-disclosure.
  for (const { requestedElement, alternativeElementSets } of options.alternatives ?? []) {
    if (!namespaces.get(requestedElement[0])?.has(requestedElement[1])) continue
    for (const [alternativeNamespace, alternativeIdentifier] of alternativeElementSets.flat()) {
      const element = lookup(alternativeNamespace, alternativeIdentifier)
      if (element) usedElements.add(element)
    }
  }

  return {
    claims,
    unusedElements: available
      .filter((element) => !usedElements.has(element))
      .map(({ issuerSignedItem: _, ...element }) => element),
  }
}

const toClaimsMatchResult = (claims: Array<ElementMatch>): ClaimsMatchResult => {
  const validClaims = claims.flatMap(({ claim }) => (claim.success ? [claim] : []))
  const failedClaims = claims.flatMap(({ claim }) => (claim.success ? [] : [claim]))

  if (isNonEmptyArray(failedClaims) && failedClaims.some((claim) => !claim.optional)) {
    return { success: false, validClaims, failedClaims }
  }

  // Every failed claim is optional, and optional elements never make the claims fail.
  return { success: true, validClaims, failedClaims: failedClaims.filter(isOptionalClaim) }
}

const isOptionalClaim = (claim: ClaimMatchFailure): claim is ClaimMatchFailure & { optional: true } => claim.optional

/**
 * The match options per doc request index, after checking that every option refers to a doc request
 * of the device request, and that no doc request has options more than once.
 */
const indexDocRequestOptions = (deviceRequest: DeviceRequest, matchOptions?: DeviceRequestMatchOptions) => {
  const docRequestOptions = new Map<number, DocRequestMatchOptions>()

  for (const options of matchOptions?.docRequests ?? []) {
    const { docRequestIndex } = options
    if (
      !Number.isInteger(docRequestIndex) ||
      docRequestIndex < 0 ||
      docRequestIndex >= deviceRequest.docRequests.length
    ) {
      throw new InvalidDeviceRequestMatchOptionsError(
        `Match options refer to doc request ${docRequestIndex}, but the device request has ${deviceRequest.docRequests.length} doc request(s)`
      )
    }
    if (docRequestOptions.has(docRequestIndex)) {
      throw new InvalidDeviceRequestMatchOptionsError(
        `Match options are provided more than once for doc request ${docRequestIndex}`
      )
    }
    docRequestOptions.set(docRequestIndex, options)
  }

  return docRequestOptions
}

/**
 * Throw an `InvalidDeviceRequestMatchOptionsError` when the match options do not fit the device
 * request, so that verification can fail on them before it does any work.
 *
 * @internal
 */
export const validateDeviceRequestMatchOptions = (
  deviceRequest: DeviceRequest,
  matchOptions?: DeviceRequestMatchOptions
) => {
  indexDocRequestOptions(deviceRequest, matchOptions)
}

const isNonEmptyArray = <T>(array: Array<T>): array is NonEmptyArray<T> => array.length > 0

const isSuccess = <T extends { success: boolean }>(result: T): result is Extract<T, { success: true }> => result.success

/**
 * The element that answers a request for `elementIdentifier`, either by identifier or, for an age
 * attestation, by the substitution 18013-5 7.2.5 allows.
 *
 * @internal
 */
export const findElement = <Candidate extends { elementIdentifier: DataElementIdentifier; elementValue: unknown }>(
  elementIdentifier: DataElementIdentifier,
  candidates: Array<Candidate>
) =>
  candidates.find((candidate) => candidate.elementIdentifier === elementIdentifier) ??
  findAgeOverCandidate(elementIdentifier, candidates)

const collectElements = (issuerSigned: IssuerSigned, deviceNamespaces?: DeviceNamespaces) => {
  const elements: Array<ElementCandidate> = []

  for (const [namespace, issuerSignedItems] of issuerSigned.issuerNamespaces?.issuerNamespaces ?? []) {
    for (const issuerSignedItem of issuerSignedItems) {
      elements.push({
        namespace,
        elementIdentifier: issuerSignedItem.elementIdentifier,
        elementValue: issuerSignedItem.elementValue,
        source: 'issuerSigned',
        issuerSignedItem,
      })
    }
  }

  for (const [namespace, deviceSignedItems] of deviceNamespaces?.deviceNamespaces ?? []) {
    for (const [elementIdentifier, elementValue] of deviceSignedItems.deviceSignedItems) {
      elements.push({ namespace, elementIdentifier, elementValue, source: 'deviceSigned' })
    }
  }

  return elements
}

/**
 * Report a {@link DeviceRequestMatchResult} through a verification callback.
 *
 * A doc request that is not satisfied is a `FAILED` check; over-disclosure and documents that were
 * never requested are reported as `WARNING`, as they are the mdoc's doing and it is up to the
 * verifier whether to accept the response anyway. When the doc requests are matched as alternatives,
 * a single check is reported instead, which only fails when none of them is satisfied, and when the
 * device request carries use cases, one check per mandatory use case and one for "at least one".
 *
 * The match is attached to the doc request checks as their structured `result`, so that it survives
 * a callback that throws on a `FAILED` check instead of collecting them.
 */
export const reportDeviceRequestMatch = (match: DeviceRequestMatchResult, onCheck: VerificationCallback) => {
  const result = { type: 'deviceRequestMatch', match } as const
  const failureReasons = (docRequestIndexes: Array<number>) =>
    match.docRequests
      .filter((docRequest) => !docRequest.success && docRequestIndexes.includes(docRequest.docRequestIndex))
      .map((docRequest) => `Doc request ${docRequest.docRequestIndex}: ${docRequestFailureReason(docRequest)}`)
      .join('. ')

  if (match.useCasesSource === 'deviceRequestInfo') {
    // A mandatory use case is a check of its own; an optional one only counts towards "at least one".
    for (const useCase of match.useCases) {
      if (!useCase.mandatory) continue
      const check = `Device response must satisfy mandatory use case ${useCase.useCaseIndex}`
      if (useCase.success) {
        onCheck({ status: 'PASSED', check, category: 'DOCUMENT_FORMAT', result })
      } else {
        onCheck({
          status: 'FAILED',
          check,
          category: 'DOCUMENT_FORMAT',
          reason: `None of the document sets of use case ${useCase.useCaseIndex} has all its doc requests satisfied. ${failureReasons(useCase.documentSets.flat())}`,
          result,
        })
      }
    }

    const check = 'Device response must satisfy at least one use case'
    if (match.useCases.some((useCase) => useCase.success)) {
      onCheck({ status: 'PASSED', check, category: 'DOCUMENT_FORMAT', result })
    } else {
      onCheck({
        status: 'FAILED',
        check,
        category: 'DOCUMENT_FORMAT',
        reason: `No use case is satisfied. ${failureReasons(match.useCases.flatMap((useCase) => useCase.documentSets.flat()))}`,
        result,
      })
    }
  } else if (match.useCasesSource === 'eachDocRequest') {
    const check = `Device response must satisfy at least one of the alternative doc requests ${match.docRequests
      .map((docRequest) => `${docRequest.docRequestIndex} for docType '${docRequest.docType}'`)
      .join(', ')}`

    if (match.success) {
      onCheck({ status: 'PASSED', check, category: 'DOCUMENT_FORMAT', result })
    } else {
      onCheck({
        status: 'FAILED',
        check,
        category: 'DOCUMENT_FORMAT',
        reason: match.docRequests
          .map((docRequest) => `Doc request ${docRequest.docRequestIndex}: ${docRequestFailureReason(docRequest)}`)
          .join('. '),
        result,
      })
    }
  } else {
    for (const docRequest of match.docRequests) {
      const check = `Device response must satisfy doc request ${docRequest.docRequestIndex} for docType '${docRequest.docType}'`

      if (docRequest.success) {
        onCheck({ status: 'PASSED', check, category: 'DOCUMENT_FORMAT', result })
      } else {
        onCheck({
          status: 'FAILED',
          check,
          category: 'DOCUMENT_FORMAT',
          reason: docRequestFailureReason(docRequest),
          result,
        })
      }
    }
  }

  for (const { documentIndex, docRequestIndexes, unrequestedClaims } of findOverDisclosure(match)) {
    const docRequests =
      docRequestIndexes.length === 1
        ? `doc request ${docRequestIndexes[0]}`
        : `doc requests ${docRequestIndexes.join(', ')}`

    onCheck({
      status: 'WARNING',
      check: `Document ${documentIndex} must not disclose elements that were not requested`,
      category: 'DOCUMENT_FORMAT',
      reason: `Document ${documentIndex} disclosed ${unrequestedClaims
        .map((claim) => `'${claim.elementIdentifier}' in namespace '${claim.namespace}'`)
        .join(', ')}, which ${docRequests} did not ask for`,
    })
  }

  if (match.unrequestedDocuments.length > 0) {
    onCheck({
      status: 'WARNING',
      check: 'Device response must not contain documents that were not requested',
      category: 'DOCUMENT_FORMAT',
      reason: `Device response contains ${match.unrequestedDocuments
        .map((document) => `document ${document.documentIndex} with docType '${document.docType}'`)
        .join(', ')}, which the device request did not ask for`,
    })
  }
}

/**
 * Per document, the elements it disclosed that no doc request it may answer asked for, in response
 * order. The response does not say which doc request a document answers, so every doc request of
 * its docType is considered, also one the document fails: with two doc requests of the same
 * docType, an element is only over-disclosed when neither asks for it. A document of another docType
 * does not answer the doc request, and is reported as an unrequested document instead.
 */
const findOverDisclosure = (match: DeviceRequestMatchResult) => {
  const documents = new Map<number, { docRequestIndexes: Array<number>; unrequestedClaims: Array<DisclosedElement> }>()

  for (const docRequest of match.docRequests) {
    for (const document of [...docRequest.validDocuments, ...docRequest.failedDocuments]) {
      if (!document.docType.success) continue

      const { unrequestedClaims } = document.claims
      const overDisclosure = documents.get(document.documentIndex)
      if (!overDisclosure) {
        documents.set(document.documentIndex, { docRequestIndexes: [docRequest.docRequestIndex], unrequestedClaims })
        continue
      }

      overDisclosure.docRequestIndexes.push(docRequest.docRequestIndex)
      overDisclosure.unrequestedClaims = overDisclosure.unrequestedClaims.filter((claim) =>
        unrequestedClaims.some(
          (other) =>
            other.namespace === claim.namespace &&
            other.elementIdentifier === claim.elementIdentifier &&
            other.source === claim.source
        )
      )
    }
  }

  return Array.from(documents, ([documentIndex, overDisclosure]) => ({ documentIndex, ...overDisclosure }))
    .filter(({ unrequestedClaims }) => unrequestedClaims.length > 0)
    .sort((a, b) => a.documentIndex - b.documentIndex)
}

const docRequestFailureReason = (docRequest: DocRequestMatch) => {
  if (!docRequest.success && docRequest.reason) return docRequest.reason

  // Documents of another docType are not an attempt to answer this doc request.
  const documents = docRequest.failedDocuments.filter(
    (document) => document.docType.success || document.docType.docType === docRequest.docType
  )

  if (documents.length === 0) {
    return `Device response does not contain a document with docType '${docRequest.docType}'`
  }

  return documents
    .map((document) => {
      if (!document.docType.success) return `Document ${document.documentIndex}: ${document.docType.reason}`

      const failedClaims = document.claims.failedClaims.filter((claim) => !claim.optional)
      const reasons = [
        ...(document.issuer && !document.issuer.success ? [document.issuer.reason] : []),
        ...failedClaims.map((claim) => claim.reason),
      ]
      return `Document ${document.documentIndex}: ${reasons.join('; ')}`
    })
    .join('. ')
}
