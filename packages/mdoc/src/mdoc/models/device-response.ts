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
  matchDeviceRequest,
  matchElements,
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
} from '../errors'
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
import type { IssuerAuthVerificationResult } from './issuer-auth'
import { IssuerNamespaces } from './issuer-namespaces'
import { IssuerSigned } from './issuer-signed'
import type { IssuerSignedItem } from './issuer-signed-item'
import type { KeyAuthorizations } from './key-authorizations'
import type { Namespace } from './namespace'
import type { SessionTranscript } from './session-transcript'

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
   * Index into `deviceRequest.docRequests` of the doc request this document answers.
   */
  docRequestIndex: number
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
   * Values to disclose device-signed. Every selected requested element that is not issuer-signed,
   * but that the device key is authorized for in the MSO, has to be provided here. Only the values
   * of selected requested elements are disclosed and authenticated, so a value that is not requested
   * or that `elements` leaves out is not.
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
   * Create a single disclosed `Document` for one `DocRequest`, authenticated with either a
   * device signature or a device MAC.
   */
  private static async createDocument(
    options: {
      docRequest: DocRequest
      docRequestIndex: number
      sessionTranscript: SessionTranscript | Uint8Array
      issuerSigned: IssuerSigned
      elements?: Record<Namespace, Array<DataElementIdentifier>>
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

    const { docRequest } = options
    const docType = docRequest.itemsRequest.docType

    // Every access to the mobile security object decodes it, so decode it once.
    const mobileSecurityObject = options.issuerSigned.issuerAuth.mobileSecurityObject
    const { keyAuthorizations } = mobileSecurityObject.deviceKeyInfo

    // The document is labeled with the requested docType, which is not signed, so a credential of
    // another docType would produce a document every reader has to reject.
    if (mobileSecurityObject.docType !== docType) {
      throw new DocTypeMismatchError(
        `Credential has docType '${mobileSecurityObject.docType}', but doc request ${options.docRequestIndex} requests docType '${docType}'`
      )
    }

    // Only the selected elements are disclosed, so values in `deviceNamespaces` that are not requested
    // do not need to be authorized, the same as `Holder.matchDeviceRequest` ignores them.
    const { issuerNamespaces: disclosedIssuerNamespaces, deviceNamespaces } = DeviceResponse.selectElements({
      docRequest,
      issuerSigned: options.issuerSigned,
      keyAuthorizations,
      deviceNamespaces: options.deviceNamespaces,
      elements: options.elements,
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
   * Only the selected requested elements are disclosed, from either source: a device-signed element
   * that is not requested, or that `elements` leaves out, is not disclosed.
   */
  private static selectElements(options: {
    docRequest: DocRequest
    issuerSigned: IssuerSigned
    keyAuthorizations: KeyAuthorizations | undefined
    deviceNamespaces?: DeviceNamespaces
    elements?: Record<Namespace, Array<DataElementIdentifier>>
  }) {
    const { claims } = matchElements({
      mode: 'holder',
      namespaces: options.docRequest.itemsRequest.namespaces,
      issuerSigned: options.issuerSigned,
      keyAuthorizations: options.keyAuthorizations,
      deviceNamespaces: options.deviceNamespaces,
    })

    if (options.elements) {
      for (const [namespace, elementIdentifiers] of Object.entries(options.elements)) {
        for (const elementIdentifier of elementIdentifiers) {
          if (!options.docRequest.itemsRequest.namespaces.get(namespace)?.has(elementIdentifier)) {
            throw new InvalidElementSelectionError(
              `Element '${elementIdentifier}' in namespace '${namespace}' is selected for disclosure, but the doc request does not request it`
            )
          }
        }
      }
    }

    const isSelected = ({ namespace, elementIdentifier }: ClaimMatch) =>
      options.elements ? (getOwnProperty(options.elements, namespace)?.includes(elementIdentifier) ?? false) : true

    // The element that answers each requested element left out of the selection, with that claim.
    const declinedElements = new Map(
      claims.flatMap(({ claim, element }) => (element && !isSelected(claim) ? [[element, claim] as const] : []))
    )

    const issuerNamespaces = new Map<Namespace, Array<IssuerSignedItem>>()
    const deviceNamespaces = new Map<Namespace, Map<DataElementIdentifier, DataElementValue>>()
    for (const match of claims) {
      const { claim } = match
      if (!isSelected(claim)) continue

      if (match.element === undefined) throw new MissingRequestedElementError(match.claim.reason)
      const { element } = match

      // An age attestation can answer more than one `age_over_NN` request (18013-5 7.2.5).
      // Disclosing it for this element would also answer a requested element that is left out, so
      // leaving that one out would have no effect.
      const declined = declinedElements.get(element)
      if (declined) {
        throw new InvalidElementSelectionError(
          `Element '${claim.elementIdentifier}' in namespace '${claim.namespace}' is selected for disclosure, but it is answered with '${element.elementIdentifier}', which also answers '${declined.elementIdentifier}' that is not selected. Select both or neither`
        )
      }

      if (!element.issuerSignedItem) {
        const items = deviceNamespaces.get(element.namespace) ?? new Map()
        items.set(element.elementIdentifier, element.elementValue)
        deviceNamespaces.set(element.namespace, items)
        continue
      }

      const items = issuerNamespaces.get(claim.namespace) ?? []
      // An age attestation can answer more than one `age_over_NN` request, but is disclosed once.
      if (!items.includes(element.issuerSignedItem)) items.push(element.issuerSignedItem)
      issuerNamespaces.set(claim.namespace, items)
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
        `Doc request would be answered with ${describeAgeOverLimitViolations(ageOverLimitViolations)}, but at most two age_over_NN elements may be disclosed per namespace. Select at most two of them`
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

  private static findDocRequest(deviceRequest: DeviceRequest, docRequestIndex: number): DocRequest {
    const docRequest = deviceRequest.docRequests[docRequestIndex]
    if (!docRequest) throw new Error(`No doc request found at index ${docRequestIndex}`)

    return docRequest
  }

  /**
   * Create a device response for a device request.
   *
   * Every document brings its own device key and, optionally, its own device namespaces, and names
   * the doc request it answers through `docRequestIndex`, so a request may also be answered
   * partially.
   */
  public static async createWithDeviceRequest(
    options: {
      deviceRequest: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      documents: Array<DeviceResponseDocumentOptions>
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    const documents = await Promise.all(
      options.documents.map((document) =>
        DeviceResponse.createDocument(
          {
            docRequest: DeviceResponse.findDocRequest(options.deviceRequest, document.docRequestIndex),
            docRequestIndex: document.docRequestIndex,
            sessionTranscript: options.sessionTranscript,
            issuerSigned: document.issuerSigned,
            elements: document.elements,
            deviceNamespaces: document.deviceNamespaces,
            signature: document.signature,
            mac: document.mac,
          },
          ctx
        )
      )
    )

    return DeviceResponse.fromDocuments(documents)
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
