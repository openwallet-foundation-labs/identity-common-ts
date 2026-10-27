import {
  CborStructure,
  type CoseKey,
  MacAlgorithm,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  TypedMap,
  typedMap,
  UnprotectedHeaders,
} from '@owf/cose'
import { base64url, stringToBytes } from '@owf/identity-common'
import { z } from 'zod'
import type { MdocContext } from '../../context'
import { describeAgeOverLimitViolations, findAgeOverLimitViolations } from '../../utils/ageOver'
import { getOwnProperty } from '../../utils/getOwnProperty'
import {
  describeUnauthorizedDeviceSignedElements,
  findUnauthorizedDeviceSignedElements,
} from '../../utils/keyAuthorizations'
import {
  type ClaimMatch,
  type DeviceRequestMatchOptions,
  type DeviceRequestMatchResult,
  type ElementMatch,
  issuerAuthCertificateChain,
  matchDeviceRequest,
  matchElements,
  matchIssuer,
  reportDeviceRequestMatch,
  validateDeviceRequestMatchOptions,
} from '../../utils/matchDeviceRequest'
import { verifyVersion } from '../../utils/version'
import { defaultVerificationCallback, type VerificationCallback } from '../check-callback'
import {
  AgeOverLimitExceededError,
  DeviceKeyNotAuthorizedError,
  DocTypeMismatchError,
  EitherSignatureOrMacMustBeProvidedError,
  InvalidElementSelectionError,
  MissingRequestedElementError,
  UnsatisfiedDeviceRequestError,
} from '../errors'
import type { AlternativeDataElementsSet } from './alternative-data-elements-set'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DataElementValue } from './data-element-value'
import { DeviceAuth, type DeviceAuthOptions } from './device-auth'
import { DeviceAuthentication } from './device-authentication'
import { DeviceMac } from './device-mac'
import { DeviceNamespaces } from './device-namespaces'
import type { DeviceRequest } from './device-request'
import { DeviceSignature } from './device-signature'
import { DeviceSigned } from './device-signed'
import { DeviceSignedItems } from './device-signed-items'
import type { DocRequest } from './doc-request'
import { Document, type DocumentEncodedStructure } from './document'
import { DocumentError, type DocumentErrorStructure } from './document-error'
import type { IntentToRetain } from './intent-to-retain'
import type { IssuerAuthVerificationResult } from './issuer-auth'
import { IssuerNamespaces } from './issuer-namespaces'
import { IssuerSigned } from './issuer-signed'
import type { IssuerSignedItem } from './issuer-signed-item'
import type { KeyAuthorizations } from './key-authorizations'
import type { Namespace } from './namespace'
import type { SessionTranscript } from './session-transcript'

/**
 * Whether a requested element is answered by one of its alternative sets, which a holder only
 * discloses when it chooses one: the credential does not have the element itself.
 */
const isAnsweredByAlternative = (match: ElementMatch) => match.options?.[0].alternativeElementSetIndex !== undefined

const deviceResponseEncodedSchema = typedMap([
  ['version', z.string()],
  ['status', z.number()],
  ['documents', z.array(z.unknown()).exactOptional()],
  ['documentErrors', z.array(z.unknown()).exactOptional()],
] as const)

const deviceResponseDecodedSchema = typedMap([
  ['version', z.string()],
  ['status', z.number()],
  ['documents', z.array(z.instanceof(Document)).exactOptional()],
  ['documentErrors', z.array(z.instanceof(DocumentError)).exactOptional()],
] as const)

export type DeviceResponseEncodedStructure = z.input<typeof deviceResponseEncodedSchema>
export type DeviceResponseDecodedStructure = z.output<typeof deviceResponseDecodedSchema>

export type DeviceResponseOptions = {
  version?: string
  documents?: Array<Document>
  documentErrors?: Array<DocumentError>
  status?: number
}

export type DocumentVerificationResult = IssuerAuthVerificationResult & { document: Document }

export type DeviceResponseVerificationResult = {
  /**
   * One entry per document in the device response, in response order.
   */
  documents: Array<DocumentVerificationResult>
  /**
   * How the response matches the device request, per doc request and per requested element. Only
   * present when `deviceRequest` was provided.
   */
  deviceRequestMatch?: DeviceRequestMatchResult
}

/**
 * A single document to disclose in a device response, authenticated with either a device signature
 * or a device MAC.
 */
export type DeviceResponseDocumentOptions = {
  issuerSigned: IssuerSigned
  /**
   * Index into `deviceRequest.docRequests` of the doc request this document answers, or of every
   * doc request it answers, which then all have its docType. The document discloses the elements
   * all of them request, and counts as their document for `uniqueDocSetRequired` and the use cases.
   */
  docRequestIndex: number | Array<number>
  /**
   * The requested elements to disclose, per namespace. Defaults to every element the doc request
   * asks for. Pass a subset to leave out elements, for instance the ones the user declined to share.
   *
   * Two `age_over_NN` requests can be answered with the same age attestation (18013-5 7.2.5), which
   * `disclosedElementIdentifier` of the claims of `Holder.matchDeviceRequest` shows. Such elements
   * have to be selected together or left out together, as leaving out only one would not keep its
   * answer from being disclosed.
   */
  elements?: Record<Namespace, Array<DataElementIdentifier>>
  /**
   * For a requested element that has alternatives in the `requestInfo` of the doc request (ISO/IEC
   * TS 23220-4 7.2.1.3.2, 18013-5 second edition 10.2.4), the index into its `alternativeElementSets`
   * of the set to disclose in its place, per namespace and element. For a document that answers
   * several doc requests, the ones that request the element must have the same alternatives for it. Every element of the set is
   * disclosed, possibly in other namespaces. The `options` of the claims of `Holder.matchDeviceRequest`
   * list the sets the credential can disclose.
   *
   * An alternative set is only disclosed when it is chosen here, so that nothing is disclosed that
   * the holder was not shown. By default the element itself is disclosed, and a requested element the
   * credential does not have throws a `MissingRequestedElementError`, even when an alternative set
   * could answer it.
   *
   * Throws an `InvalidElementSelectionError` for an element the doc request does not request, a set
   * it does not have, an element that `elements` leaves out, a set that discloses an element that
   * `elements` leaves out, or an element that the doc requests of the document have different
   * alternatives for; and a `MissingRequestedElementError` for a set the credential does not have
   * every element of.
   */
  alternatives?: Record<Namespace, Record<DataElementIdentifier, number>>
  /**
   * Values to disclose device-signed. Every selected requested element that is not issuer-signed,
   * but that the device key is authorized for in the MSO, has to be provided here. Only the values
   * of selected requested elements, and of the alternative sets chosen in `alternatives`, are
   * disclosed and authenticated, so a value that is not requested or that `elements` leaves out is
   * not.
   */
  deviceNamespaces?: DeviceNamespaces
  signature?: {
    signingKey: CoseKey
  }
  mac?: {
    ephemeralKey: CoseKey
    signingKey: CoseKey
  }
}

export class DeviceResponse extends CborStructure<DeviceResponseEncodedStructure, DeviceResponseDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(deviceResponseEncodedSchema.in, deviceResponseDecodedSchema.out, {
      decode: (input) => {
        const map = TypedMap.fromMap(input) as DeviceResponseDecodedStructure

        if (input.has('documents')) {
          map.set(
            'documents',
            (input.get('documents') as unknown[]).map((d) =>
              Document.fromEncodedStructure(d as DocumentEncodedStructure)
            )
          )
        }

        if (input.has('documentErrors')) {
          map.set(
            'documentErrors',
            (input.get('documentErrors') as unknown[]).map((d) =>
              DocumentError.fromEncodedStructure(d as DocumentErrorStructure)
            )
          )
        }

        return map
      },
      encode: (output) => {
        const map: Map<unknown, unknown> = output.toMap()

        const documents = output.get('documents')
        if (documents !== undefined) {
          map.set(
            'documents',
            documents.map((d) => d.encodedStructure)
          )
        }

        const documentErrors = output.get('documentErrors')
        if (documentErrors !== undefined) {
          map.set(
            'documentErrors',
            documentErrors.map((d) => d.encodedStructure)
          )
        }

        return map
      },
    })
  }

  public get version() {
    return this.structure.get('version')
  }

  public get documents() {
    return this.structure.get('documents')
  }

  public get documentErrors() {
    return this.structure.get('documentErrors')
  }

  public get status() {
    return this.structure.get('status')
  }

  public async verify(
    options: {
      deviceRequest?: DeviceRequest
      deviceRequestMatchOptions?: DeviceRequestMatchOptions
      sessionTranscript: SessionTranscript | Uint8Array
      ephemeralReaderKey?: CoseKey
      disableCertificateChainValidation?: boolean
      disableStatusValidation?: boolean
      trustedCertificates: Array<{ issuance: Uint8Array[]; status?: Uint8Array[] }>
      now?: Date
      onCheck?: VerificationCallback
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'cose' | 'x509' | 'crypto' | 'fetch'>
  ): Promise<DeviceResponseVerificationResult> {
    const onCheck = options.onCheck ?? defaultVerificationCallback

    // Invalid match options are a mistake of the caller, so fail on them before verifying anything.
    if (options.deviceRequest) {
      validateDeviceRequestMatchOptions(options.deviceRequest, options.deviceRequestMatchOptions)
    }

    verifyVersion({ structure: 'Device Response', version: this.structure.get('version') }, onCheck)

    const documents = this.structure.get('documents')
    onCheck({
      status: !documents || documents.length > 0 ? 'PASSED' : 'FAILED',
      check: 'Device Response must not include documents or at least one document.',
      category: 'DOCUMENT_FORMAT',
    })

    // 18013-5 8.3.2.1.2.3 Table 8: an mdoc returning a status other than 0 must not return documents.
    const status = this.structure.get('status')
    onCheck({
      status: status === 0 || !documents?.length ? 'PASSED' : 'FAILED',
      check: 'Device Response must not include documents when the status is not 0.',
      category: 'DOCUMENT_FORMAT',
      reason:
        status !== 0 && documents?.length
          ? `Device Response has status ${status} but returned ${documents.length} document(s)`
          : undefined,
    })

    const documentResults: Array<DocumentVerificationResult> = []
    for (const document of documents ?? []) {
      await document.deviceSigned.deviceAuth.verify(
        {
          document,
          ephemeralMacPrivateKey: options.ephemeralReaderKey,
          sessionTranscript: options.sessionTranscript,
          verificationCallback: onCheck,
        },
        ctx
      )

      const { trustedIssuanceChain, statusList, trustedStatusListChain, identifierList, trustedIdentifierListChain } =
        await document.issuerSigned.verify(
          {
            verificationCallback: onCheck,
            disableCertificateChainValidation: options.disableCertificateChainValidation,
            now: options.now,
            trustedCertificates: options.trustedCertificates,
            skewSeconds: options.skewSeconds,
            disableStatusValidation: options.disableStatusValidation,
          },
          ctx
        )

      // 18013-5 9.3.1 step 4: the docType of the document is not signed, so it must be the docType of
      // the MSO, whether or not a device request is matched.
      const mobileSecurityObjectDocType = document.issuerSigned.issuerAuth.mobileSecurityObject.docType
      onCheck({
        status: document.docType === mobileSecurityObjectDocType ? 'PASSED' : 'FAILED',
        check: 'The docType of the document must match the docType of the mobile security object.',
        category: 'ISSUER_AUTH',
        reason:
          document.docType !== mobileSecurityObjectDocType
            ? `Document has docType '${document.docType}', but the mobile security object has docType '${mobileSecurityObjectDocType}'`
            : undefined,
      })

      documentResults.push({
        trustedIssuanceChain,
        statusList,
        trustedStatusListChain,
        identifierList,
        trustedIdentifierListChain,
        document,
      })
    }

    let deviceRequestMatch: DeviceRequestMatchResult | undefined
    if (options.deviceRequest) {
      deviceRequestMatch = matchDeviceRequest({
        deviceRequest: options.deviceRequest,
        deviceResponse: this,
        matchOptions: options.deviceRequestMatchOptions,
        // The x5chain is not signed, so issuers are matched against the validated chains.
        issuerCertificateChains: documentResults.map(({ trustedIssuanceChain }) => trustedIssuanceChain),
      })
      reportDeviceRequestMatch(deviceRequestMatch, onCheck)
    }

    return { documents: documentResults, deviceRequestMatch }
  }

  public get encodedForOid4Vp() {
    return base64url.encode(this.encode())
  }

  public static fromEncodedForOid4Vp(encoded: string): DeviceResponse {
    return DeviceResponse.decode(base64url.decode(encoded))
  }

  /**
   * Create a single disclosed `Document` for the doc requests it answers, authenticated with either a
   * device signature or a device MAC.
   */
  private static async createDocument(
    options: {
      docRequests: Array<{ docRequestIndex: number; docRequest: DocRequest }>
      sessionTranscript: SessionTranscript | Uint8Array
      issuerSigned: IssuerSigned
      elements?: Record<Namespace, Array<DataElementIdentifier>>
      alternatives?: Record<Namespace, Record<DataElementIdentifier, number>>
      deviceNamespaces?: DeviceNamespaces
      signature?: {
        signingKey: CoseKey
      }
      mac?: {
        ephemeralKey: CoseKey
        signingKey: CoseKey
      }
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    const useMac = !!options.mac
    const useSignature = !!options.signature
    if (useMac === useSignature) throw new EitherSignatureOrMacMustBeProvidedError()

    const signingKey = useSignature ? options.signature?.signingKey : options.mac?.signingKey
    if (!signingKey) throw new Error('Signing key is missing')

    // Every access to the mobile security object decodes it, so decode it once.
    const mobileSecurityObject = options.issuerSigned.issuerAuth.mobileSecurityObject
    const { keyAuthorizations } = mobileSecurityObject.deviceKeyInfo
    const docType = mobileSecurityObject.docType

    // The document is labeled with the requested docType, which is not signed, so a credential of
    // another docType would produce a document every reader has to reject.
    for (const { docRequestIndex, docRequest } of options.docRequests) {
      if (docRequest.itemsRequest.docType !== docType) {
        throw new DocTypeMismatchError(
          `Credential has docType '${docType}', but doc request ${docRequestIndex} requests docType '${docRequest.itemsRequest.docType}'`
        )
      }
    }

    // Only the selected elements are disclosed, so values in `deviceNamespaces` that are not requested
    // do not need to be authorized, the same as `Holder.matchDeviceRequest` ignores them.
    const { issuerNamespaces: disclosedIssuerNamespaces, deviceNamespaces } = DeviceResponse.selectElements({
      ...DeviceResponse.mergeDocRequests(options.docRequests),
      docRequestIndexes: options.docRequests.map(({ docRequestIndex }) => docRequestIndex),
      issuerSigned: options.issuerSigned,
      keyAuthorizations,
      deviceNamespaces: options.deviceNamespaces,
      elements: options.elements,
      alternatives: options.alternatives,
    })

    // 18013-5 9.1.3.4 binds the mdoc as well as the mdoc reader. Selection only picks authorized
    // device-signed elements, so this guards that invariant rather than emit a response every reader
    // must reject.
    const unauthorized = findUnauthorizedDeviceSignedElements({ deviceNamespaces, keyAuthorizations })
    if (unauthorized.length > 0) {
      throw new DeviceKeyNotAuthorizedError(describeUnauthorizedDeviceSignedElements(unauthorized))
    }

    const deviceAuthenticationBytes = DeviceAuthentication.create({
      sessionTranscript: options.sessionTranscript,
      docType,
      deviceNamespaces,
    }).encode({ asDataItem: true })

    const unprotectedHeaders = UnprotectedHeaders.create({})
    if (signingKey.keyId) {
      // COSE label 4 (kid) is a bstr per RFC 8152; UTF-8 encode
      // the text form at the header boundary.
      unprotectedHeaders.headers?.set(RegisteredCwtHeaderClaimKey.KeyId, stringToBytes(signingKey.keyId))
    }

    const deviceAuthOptions: DeviceAuthOptions = {}
    if (useSignature) {
      const deviceSignature = await DeviceSignature.create({
        unprotectedHeaders,
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, signingKey.algorithm]]),
        }),
        payload: null,
      }).sign({ signingKey, detachedPayload: deviceAuthenticationBytes }, { sign: ctx.cose.sign1.sign })

      deviceAuthOptions.deviceSignature = deviceSignature
    } else {
      const ephemeralKey = options.mac?.ephemeralKey
      if (!ephemeralKey) throw new Error('Ephemeral key is missing')

      // 18013-5 9.1.3.5: the device MAC is always HMAC 256/256, keyed with the EMacKey derived from
      // the device key, and not with the algorithm of the device key.
      const deviceMac = DeviceMac.create({
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, MacAlgorithm.HS256]]),
        }),
        unprotectedHeaders,
        payload: null,
      })

      const macKey = await deviceMac.createDeviceMacKey(
        {
          publicKey: ephemeralKey,
          privateKey: signingKey,
          sessionTranscript: options.sessionTranscript,
        },
        ctx
      )

      await deviceMac.authenticate(
        { key: macKey, algorithm: MacAlgorithm.HS256, detachedPayload: deviceAuthenticationBytes },
        ctx.cose.mac0
      )

      deviceAuthOptions.deviceMac = deviceMac
    }

    return Document.create({
      docType,
      issuerSigned: IssuerSigned.create({
        issuerNamespaces: disclosedIssuerNamespaces,
        issuerAuth: options.issuerSigned.issuerAuth,
      }),
      deviceSigned: DeviceSigned.create({
        deviceNamespaces,
        deviceAuth: DeviceAuth.create(deviceAuthOptions),
      }),
    })
  }

  /**
   * The issuer-signed items and device-signed elements to disclose for a doc request, selected the
   * same way as `Holder.matchDeviceRequest` matches a credential: a requested element is disclosed
   * issuer-signed when the issuer signed it, and otherwise device-signed when the device key is
   * authorized for it and its value is in the device namespaces.
   *
   * Only the selected requested elements, or the alternative sets chosen for them, are disclosed,
   * from either source: a device-signed element that is not requested, or that `elements` leaves
   * out, is not disclosed.
   */
  private static selectElements(options: {
    namespaces: Map<Namespace, Map<DataElementIdentifier, IntentToRetain>>
    alternativeDataElements: Array<AlternativeDataElementsSet> | undefined
    /**
     * The requested elements that the doc requests have different alternatives for, which cannot be
     * chosen, with the doc requests that request them.
     */
    conflictingAlternatives: Array<{
      namespace: Namespace
      elementIdentifier: DataElementIdentifier
      docRequestIndexes: Array<number>
    }>
    /**
     * The doc requests the document answers, for the error messages.
     */
    docRequestIndexes: Array<number>
    issuerSigned: IssuerSigned
    keyAuthorizations: KeyAuthorizations | undefined
    deviceNamespaces?: DeviceNamespaces
    elements?: Record<Namespace, Array<DataElementIdentifier>>
    alternatives?: Record<Namespace, Record<DataElementIdentifier, number>>
  }) {
    const { claims } = matchElements({
      mode: 'holder',
      namespaces: options.namespaces,
      issuerSigned: options.issuerSigned,
      keyAuthorizations: options.keyAuthorizations,
      deviceNamespaces: options.deviceNamespaces,
      alternatives: options.alternativeDataElements,
    })

    const several = options.docRequestIndexes.length > 1
    const docRequests = several ? `doc requests ${options.docRequestIndexes.join(', ')}` : 'the doc request'
    const doNotRequest = `${docRequests} ${several ? 'do' : 'does'} not request`

    if (options.elements) {
      for (const [namespace, elementIdentifiers] of Object.entries(options.elements)) {
        for (const elementIdentifier of elementIdentifiers) {
          if (!options.namespaces.get(namespace)?.has(elementIdentifier)) {
            throw new InvalidElementSelectionError(
              `Element '${elementIdentifier}' in namespace '${namespace}' is selected for disclosure, but ${doNotRequest} it`
            )
          }
        }
      }
    }

    const isSelected = ({ namespace, elementIdentifier }: ClaimMatch) =>
      options.elements ? (getOwnProperty(options.elements, namespace)?.includes(elementIdentifier) ?? false) : true

    const requestedAlternatives = options.alternativeDataElements
    for (const [namespace, chosen] of Object.entries(options.alternatives ?? {})) {
      for (const [elementIdentifier, alternativeElementSetIndex] of Object.entries(chosen)) {
        if (!options.namespaces.get(namespace)?.has(elementIdentifier)) {
          throw new InvalidElementSelectionError(
            `Alternative set ${alternativeElementSetIndex} of element '${elementIdentifier}' in namespace '${namespace}' is selected for disclosure, but ${doNotRequest} the element`
          )
        }
        const sets = requestedAlternatives?.find(
          ({ requestedElement: [requestedNamespace, requestedIdentifier] }) =>
            requestedNamespace === namespace && requestedIdentifier === elementIdentifier
        )?.alternativeElementSets
        const conflict = options.conflictingAlternatives.find(
          (element) => element.namespace === namespace && element.elementIdentifier === elementIdentifier
        )
        if (conflict) {
          throw new InvalidElementSelectionError(
            `Alternative set ${alternativeElementSetIndex} of element '${elementIdentifier}' in namespace '${namespace}' is selected for disclosure, but doc requests ${conflict.docRequestIndexes.join(', ')} have different alternatives for it. Answer them with separate documents`
          )
        }
        if (!sets?.[alternativeElementSetIndex]) {
          throw new InvalidElementSelectionError(
            `Alternative set ${alternativeElementSetIndex} of element '${elementIdentifier}' in namespace '${namespace}' is selected for disclosure, but ${docRequests} ${several ? 'have' : 'has'} no such alternative set`
          )
        }
        if (options.elements && !getOwnProperty(options.elements, namespace)?.includes(elementIdentifier)) {
          throw new InvalidElementSelectionError(
            `Alternative set ${alternativeElementSetIndex} of element '${elementIdentifier}' in namespace '${namespace}' is selected for disclosure, but the element itself is not selected`
          )
        }
      }
    }

    // The element of each requested element left out of the selection, with that claim. One that the
    // credential does not have, and that an alternative set answers, has none to leave out.
    const declinedElements = new Map(
      claims.flatMap((match) =>
        match.element && !isAnsweredByAlternative(match) && !isSelected(match.claim)
          ? [[match.element, match.claim] as const]
          : []
      )
    )

    const issuerNamespaces = new Map<Namespace, Array<IssuerSignedItem>>()
    const deviceNamespaces = new Map<Namespace, Map<DataElementIdentifier, DataElementValue>>()
    for (const match of claims) {
      const { claim } = match
      if (!isSelected(claim)) continue

      if (match.element === undefined) {
        const conflict = options.conflictingAlternatives.find(
          (element) => element.namespace === claim.namespace && element.elementIdentifier === claim.elementIdentifier
        )
        throw new MissingRequestedElementError(
          conflict
            ? `Element '${claim.elementIdentifier}' in namespace '${claim.namespace}' is not in the credential, and doc requests ${conflict.docRequestIndexes.join(', ')} have different alternatives for it. Answer them with separate documents`
            : match.claim.reason
        )
      }
      const { element } = match

      const alternativeElementSetIndex = getOwnProperty(
        getOwnProperty(options.alternatives, claim.namespace),
        claim.elementIdentifier
      )
      const chosen =
        alternativeElementSetIndex === undefined
          ? undefined
          : match.options?.find((option) => option.alternativeElementSetIndex === alternativeElementSetIndex)
      if (alternativeElementSetIndex !== undefined && !chosen) {
        throw new MissingRequestedElementError(
          `Alternative set ${alternativeElementSetIndex} of element '${claim.elementIdentifier}' in namespace '${claim.namespace}' is selected for disclosure, but the credential cannot disclose every element of it`
        )
      }

      // An alternative set is only disclosed when the holder chooses it, so that nothing is disclosed
      // that the holder was not shown: the requested element may be answered by elements in other
      // namespaces, which the claim does not describe.
      if (isAnsweredByAlternative(match) && !chosen) {
        throw new MissingRequestedElementError(
          `Element '${claim.elementIdentifier}' in namespace '${claim.namespace}' is not in the credential. Choose one of its alternative sets ${match.options?.map((option) => option.alternativeElementSetIndex).join(', ')} with \`alternatives\` to disclose in its place`
        )
      }

      // An alternative set (18013-5 second edition 10.2.4) is disclosed whole, each element in its
      // own namespace, which need not be the requested element's.
      const disclosedElements = chosen?.elements ?? [element]

      // An element left out must not be disclosed for another requested element, neither as an age
      // attestation that answers both (18013-5 7.2.5) nor in an alternative set, or leaving it out
      // would have no effect.
      for (const disclosed of disclosedElements) {
        const declined = declinedElements.get(disclosed)
        if (!declined) continue

        const selected = `Element '${claim.elementIdentifier}' in namespace '${claim.namespace}' is selected for disclosure`
        if (!chosen) {
          throw new InvalidElementSelectionError(
            `${selected}, but it is answered with '${disclosed.elementIdentifier}', which also answers '${declined.elementIdentifier}' that is not selected. Select both or neither`
          )
        }
        const answer =
          disclosed.namespace === declined.namespace && disclosed.elementIdentifier === declined.elementIdentifier
            ? `'${disclosed.elementIdentifier}' in namespace '${disclosed.namespace}'`
            : `'${disclosed.elementIdentifier}' in namespace '${disclosed.namespace}', which answers '${declined.elementIdentifier}' in namespace '${declined.namespace}'`
        throw new InvalidElementSelectionError(
          `${selected}, but it is answered with alternative set ${chosen.alternativeElementSetIndex}, which discloses ${answer} that is not selected. Select both, or choose another alternative set`
        )
      }

      for (const disclosed of disclosedElements) {
        if (!disclosed.issuerSignedItem) {
          const items = deviceNamespaces.get(disclosed.namespace) ?? new Map()
          items.set(disclosed.elementIdentifier, disclosed.elementValue)
          deviceNamespaces.set(disclosed.namespace, items)
          continue
        }

        const items = issuerNamespaces.get(disclosed.namespace) ?? []
        // An age attestation can answer more than one `age_over_NN` request, but is disclosed once.
        if (!items.includes(disclosed.issuerSignedItem)) items.push(disclosed.issuerSignedItem)
        issuerNamespaces.set(disclosed.namespace, items)
      }
    }

    // 18013-5 7.2.5: a reader must not request more than two age attestations, as together they
    // narrow down the age of the holder. Only what is disclosed counts, so a holder can still answer
    // such a request by selecting at most two of them.
    const disclosedElementIdentifiers = new Map<Namespace, Array<DataElementIdentifier>>(
      Array.from(issuerNamespaces, ([namespace, items]) => [namespace, items.map((item) => item.elementIdentifier)])
    )
    for (const [namespace, items] of deviceNamespaces) {
      disclosedElementIdentifiers.set(namespace, [
        ...(disclosedElementIdentifiers.get(namespace) ?? []),
        ...items.keys(),
      ])
    }
    const ageOverLimitViolations = findAgeOverLimitViolations(disclosedElementIdentifiers)
    if (ageOverLimitViolations.length > 0) {
      throw new AgeOverLimitExceededError(
        `${several ? `Doc requests ${options.docRequestIndexes.join(', ')}` : 'Doc request'} would be answered with ${describeAgeOverLimitViolations(ageOverLimitViolations)}, but at most two age_over_NN elements may be disclosed per namespace. Select at most two of them${options.alternatives && Object.keys(options.alternatives).length > 0 ? ', or choose other alternative sets' : ''}`
      )
    }

    return {
      // `IssuerNameSpaces` must have at least one namespace, so it is left out when no issuer-signed
      // element is disclosed.
      issuerNamespaces: issuerNamespaces.size > 0 ? IssuerNamespaces.create({ issuerNamespaces }) : undefined,
      deviceNamespaces: DeviceNamespaces.create({
        deviceNamespaces: new Map(
          Array.from(deviceNamespaces, ([namespace, items]) => [
            namespace,
            DeviceSignedItems.create({ deviceSignedItems: items }),
          ])
        ),
      }),
    }
  }

  private static fromDocuments(documents: Array<Document>) {
    const map: DeviceResponseDecodedStructure = new TypedMap([
      ['version', '1.0'],
      ['status', 0],
      ['documents', documents],
    ])

    return DeviceResponse.fromDecodedStructure(map)
  }

  /**
   * The doc requests a document answers, from its `docRequestIndex`.
   */
  private static findDocRequests(
    deviceRequest: DeviceRequest,
    document: Pick<DeviceResponseDocumentOptions, 'docRequestIndex'>
  ) {
    const docRequestIndexes = Array.from(
      new Set(typeof document.docRequestIndex === 'number' ? [document.docRequestIndex] : document.docRequestIndex)
    )
    if (docRequestIndexes.length === 0) throw new Error('A document has to answer at least one doc request')

    return docRequestIndexes.map((docRequestIndex) => ({
      docRequestIndex,
      docRequest: DeviceResponse.findDocRequest(deviceRequest, docRequestIndex),
    }))
  }

  /**
   * What the doc requests of a document request together: every element any of them requests, and
   * its alternatives. An element that more than one of them requests with different alternatives,
   * or without alternatives in one of them, is answered by itself only: an alternative set of one
   * doc request would not answer the other.
   */
  private static mergeDocRequests(docRequests: Array<{ docRequestIndex: number; docRequest: DocRequest }>) {
    const namespaces = new Map<Namespace, Map<DataElementIdentifier, IntentToRetain>>()
    for (const { docRequest } of docRequests) {
      for (const [namespace, elements] of docRequest.itemsRequest.namespaces) {
        const merged = namespaces.get(namespace) ?? new Map<DataElementIdentifier, IntentToRetain>()
        for (const [elementIdentifier, intentToRetain] of elements) {
          merged.set(elementIdentifier, (merged.get(elementIdentifier) ?? false) || intentToRetain)
        }
        namespaces.set(namespace, merged)
      }
    }

    const alternativeDataElements: Array<AlternativeDataElementsSet> = []
    const conflictingAlternatives: Array<{
      namespace: Namespace
      elementIdentifier: DataElementIdentifier
      docRequestIndexes: Array<number>
    }> = []
    for (const [namespace, elements] of namespaces) {
      for (const elementIdentifier of elements.keys()) {
        const requesting = docRequests.filter(({ docRequest }) =>
          docRequest.itemsRequest.namespaces.get(namespace)?.has(elementIdentifier)
        )
        const alternatives = requesting.map(({ docRequest }) =>
          docRequest.itemsRequest.requestInfo?.alternativeDataElements?.find(
            ({ requestedElement: [requestedNamespace, requestedIdentifier] }) =>
              requestedNamespace === namespace && requestedIdentifier === elementIdentifier
          )
        )
        const [first] = alternatives
        if (!first) {
          if (alternatives.some((alternative) => alternative)) {
            conflictingAlternatives.push({
              namespace,
              elementIdentifier,
              docRequestIndexes: requesting.map(({ docRequestIndex }) => docRequestIndex),
            })
          }
          continue
        }
        const sameSets = (alternative: AlternativeDataElementsSet | undefined) =>
          JSON.stringify(alternative?.alternativeElementSets) === JSON.stringify(first.alternativeElementSets)
        if (alternatives.every(sameSets)) {
          alternativeDataElements.push(first)
        } else {
          conflictingAlternatives.push({
            namespace,
            elementIdentifier,
            docRequestIndexes: requesting.map(({ docRequestIndex }) => docRequestIndex),
          })
        }
      }
    }

    return {
      namespaces,
      alternativeDataElements: alternativeDataElements.length > 0 ? alternativeDataElements : undefined,
      conflictingAlternatives,
    }
  }

  private static findDocRequest(deviceRequest: DeviceRequest, docRequestIndex: number): DocRequest {
    const docRequest = deviceRequest.docRequests[docRequestIndex]
    if (!docRequest) throw new Error(`No doc request found at index ${docRequestIndex}`)

    return docRequest
  }

  /**
   * Throw an `UnsatisfiedDeviceRequestError` when the documents do not answer the device request the
   * way its request information asks (ISO/IEC TS 23220-4 7.2.1.3): a document of an issuer its doc
   * request does not name, more than one document for a doc request that requires a unique document
   * set, or, when the device request carries use cases, a mandatory use case, or every use case, left
   * without a document set whose doc requests all have a document.
   *
   * Only which doc requests get a document is checked, not which elements are disclosed, so the
   * holder can still leave elements out. A doc request has a document when a document names it in
   * its `docRequestIndex`, as one document can answer several doc requests. A response without any
   * document is not checked, as that is how a holder declines a request it
   * cannot or does not want to satisfy (18013-5 second edition 10.2.1).
   *
   * A device request without use cases does not say whether it asks for all its doc requests or for
   * any one of them: ISO/IEC TS 23220-4 7.2.1.3.2 reads it as all of them, but the iOS DC API presents
   * it as alternatives, so readers use it that way (see `treatAmbiguousMultipleDocRequestsAsAlternatives`).
   * Which doc requests get a document is then not checked.
   */
  private static checkRequestInfo(deviceRequest: DeviceRequest, documents: Array<DeviceResponseDocumentOptions>) {
    const documentsPerDocRequest = new Map<number, number>()

    for (const [documentIndex, document] of documents.entries()) {
      for (const { docRequestIndex, docRequest } of DeviceResponse.findDocRequests(deviceRequest, document)) {
        const { requestInfo } = docRequest.itemsRequest
        documentsPerDocRequest.set(docRequestIndex, (documentsPerDocRequest.get(docRequestIndex) ?? 0) + 1)

        const issuer = matchIssuer(
          requestInfo?.issuerIdentifiers,
          issuerAuthCertificateChain(document.issuerSigned),
          'x5chain of the IssuerAuth'
        )
        if (issuer && !issuer.success) {
          throw new UnsatisfiedDeviceRequestError(
            `Document ${documentIndex} answers doc request ${docRequestIndex}, but comes from an issuer it does not accept: ${issuer.reason}`
          )
        }

        if (requestInfo?.uniqueDocSetRequired && documentsPerDocRequest.get(docRequestIndex) === 2) {
          throw new UnsatisfiedDeviceRequestError(
            `More than one document answers doc request ${docRequestIndex}, but it requires a unique document set`
          )
        }
      }
    }

    const useCases = deviceRequest.deviceRequestInfo?.useCases
    if (!useCases || documents.length === 0) return

    const hasDocument = (docRequestIndex: number) => documentsPerDocRequest.has(docRequestIndex)
    const isSatisfied = (documentSets: Array<Array<number>>) => documentSets.some((set) => set.every(hasDocument))
    const answered = `they answer doc requests ${Array.from(documentsPerDocRequest.keys())
      .sort((a, b) => a - b)
      .join(', ')}`

    for (const [useCaseIndex, useCase] of useCases.entries()) {
      if (useCase.mandatory && !isSatisfied(useCase.documentSets)) {
        throw new UnsatisfiedDeviceRequestError(
          `Use case ${useCaseIndex} is mandatory, but the documents do not answer every doc request of any of its document sets (${answered})`
        )
      }
    }
    if (!useCases.some((useCase) => isSatisfied(useCase.documentSets))) {
      throw new UnsatisfiedDeviceRequestError(
        `None of the use cases has a document set whose doc requests the documents all answer (${answered})`
      )
    }
  }

  /**
   * Throw an `UnsatisfiedDeviceRequestError` when the response is larger than the smallest
   * `maximumResponseSize` of the doc requests, the size in bytes of the unencrypted device response
   * the reader can accept (ISO/IEC TS 23220-4 7.2.1.3.2).
   */
  private static checkResponseSize(deviceRequest: DeviceRequest, deviceResponse: DeviceResponse) {
    const limits = deviceRequest.docRequests.flatMap((docRequest, docRequestIndex) => {
      const maximumResponseSize = docRequest.itemsRequest.requestInfo?.maximumResponseSize
      return maximumResponseSize === undefined ? [] : [{ docRequestIndex, maximumResponseSize }]
    })
    if (limits.length === 0) return

    const limit = limits.reduce((smallest, current) =>
      current.maximumResponseSize < smallest.maximumResponseSize ? current : smallest
    )
    const size = deviceResponse.encode().length
    if (size > limit.maximumResponseSize) {
      throw new UnsatisfiedDeviceRequestError(
        `The device response is ${size} bytes, but doc request ${limit.docRequestIndex} accepts at most ${limit.maximumResponseSize}. Leave out elements or documents`
      )
    }
  }

  /**
   * Create a device response for a device request.
   *
   * Every document brings its own device key and, optionally, its own device namespaces, and names
   * the doc requests it answers through `docRequestIndex`. Elements and doc requests may be left out,
   * as long as the response still answers the request the way its request information asks: see
   * `Holder.createDeviceResponseForDeviceRequest` for what is refused.
   */
  public static async createWithDeviceRequest(
    options: {
      deviceRequest: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      documents: Array<DeviceResponseDocumentOptions>
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    DeviceResponse.checkRequestInfo(options.deviceRequest, options.documents)

    const documents = await Promise.all(
      options.documents.map((document) =>
        DeviceResponse.createDocument(
          {
            docRequests: DeviceResponse.findDocRequests(options.deviceRequest, document),
            sessionTranscript: options.sessionTranscript,
            issuerSigned: document.issuerSigned,
            elements: document.elements,
            alternatives: document.alternatives,
            deviceNamespaces: document.deviceNamespaces,
            signature: document.signature,
            mac: document.mac,
          },
          ctx
        )
      )
    )

    const deviceResponse = DeviceResponse.fromDocuments(documents)
    DeviceResponse.checkResponseSize(options.deviceRequest, deviceResponse)
    return deviceResponse
  }

  public static createSimple(options: DeviceResponseOptions): DeviceResponse {
    const map: DeviceResponseDecodedStructure = new TypedMap([
      ['version', options.version ?? '1.0'],
      ['status', options.status ?? 0],
    ])

    if (options.documents !== undefined) {
      map.set('documents', options.documents)
    }

    if (options.documentErrors !== undefined) {
      map.set('documentErrors', options.documentErrors)
    }

    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(map)
  }
}
