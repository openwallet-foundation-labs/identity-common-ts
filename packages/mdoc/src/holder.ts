import { base64url } from '@owf/identity-common'
import type { MdocContext } from './context'
import {
  DeviceRequest,
  DeviceResponse,
  type DeviceResponseDocumentOptions,
  defaultVerificationCallback,
  IssuerSigned,
  type IssuerSignedVerificationResult,
  SessionTranscript,
  type VerificationCallback,
} from './mdoc'
import { verifyAgeOverRequestLimit } from './utils/ageOver'
import {
  type HolderCredential,
  type HolderDeviceRequestMatchResult,
  matchCredentialsToDeviceRequest,
} from './utils/matchDeviceRequest'
import { verifyVersion } from './utils/version'

// biome-ignore lint/complexity/noStaticOnlyClass: part of the public API
export class Holder {
  /**
   * A string `issuerSigned` is base64url encoded, as OpenID4VCI defines it.
   */
  public static async verifyIssuerSigned(
    options: {
      issuerSigned: Uint8Array | string | IssuerSigned
      verificationCallback?: VerificationCallback
      now?: Date
      disableCertificateChainValidation?: boolean
      disableStatusValidation?: boolean
      trustedCertificates?: Array<{ issuance: Uint8Array[]; status?: Uint8Array[] }>
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'cose' | 'x509' | 'crypto' | 'fetch'>
  ): Promise<IssuerSignedVerificationResult> {
    const issuerSigned =
      typeof options.issuerSigned === 'string'
        ? IssuerSigned.decode(base64url.decode(options.issuerSigned))
        : options.issuerSigned instanceof Uint8Array
          ? IssuerSigned.decode(options.issuerSigned)
          : options.issuerSigned

    return await issuerSigned.verify(options, ctx)
  }

  public static async verifyDeviceRequest(
    options: {
      deviceRequest: Uint8Array | DeviceRequest
      sessionTranscript: Uint8Array | SessionTranscript
      verificationCallback?: VerificationCallback
      /**
       * Trust anchors for the reader's certificate chain. Each
       * `DocRequest.readerAuth` chain is validated against these anchors (e.g.
       * CAs listed in a RICAL — Reader Identification CA List, defined in
       * ISO/IEC 18013-5 second edition Annex F).
       *
       * Without trust anchors the chain check of a request with reader auth
       * FAILS, unless `disableCertificateChainValidation` is set.
       */
      trustedCertificates?: Array<Uint8Array>
      /**
       * Only verify reader-auth signatures, without establishing trust in the
       * reader's certificate chain.
       */
      disableCertificateChainValidation?: boolean
      /**
       * Reference time for certificate `notBefore`/`notAfter` checks during
       * chain validation. Defaults to the current time.
       */
      now?: Date
    },
    ctx: Pick<MdocContext, 'cose' | 'x509'>
  ) {
    const deviceRequest =
      options.deviceRequest instanceof DeviceRequest
        ? options.deviceRequest
        : DeviceRequest.decode(options.deviceRequest)

    const sessionTranscript = SessionTranscript.from(options.sessionTranscript)

    const onCheck = options.verificationCallback ?? defaultVerificationCallback
    verifyVersion({ structure: 'Device Request', version: deviceRequest.version }, onCheck)
    verifyAgeOverRequestLimit(deviceRequest, onCheck)

    for (const docRequest of deviceRequest.docRequests) {
      await docRequest.readerAuth?.verify(
        {
          readerAuthentication: {
            itemsRequest: docRequest.itemsRequest,
            sessionTranscript,
          },
          verificationCallback: options.verificationCallback,
          trustedCertificates: options.trustedCertificates,
          disableCertificateChainValidation: options.disableCertificateChainValidation,
          now: options.now,
        },
        ctx
      )
    }
  }

  /**
   * Match the credentials of the holder against a device request, to select which credentials can
   * answer which doc request. See {@link matchCredentialsToDeviceRequest} for what is matched.
   *
   * `createDeviceResponseForDeviceRequest` selects the elements to disclose the same way, so a
   * credential that matches can answer the doc request with the same `deviceNamespaces`. A requested
   * element the credential only answers with an alternative set is the exception: the holder has to
   * choose the set with `alternatives`.
   */
  public static matchDeviceRequest(options: {
    deviceRequest: Uint8Array | DeviceRequest
    credentials: Array<IssuerSigned | HolderCredential>
    /**
     * See `DeviceRequestMatchOptions.treatAmbiguousMultipleDocRequestsAsAlternatives`. Defaults to
     * `false`.
     */
    treatAmbiguousMultipleDocRequestsAsAlternatives?: boolean
  }): HolderDeviceRequestMatchResult {
    return matchCredentialsToDeviceRequest({
      deviceRequest:
        options.deviceRequest instanceof DeviceRequest
          ? options.deviceRequest
          : DeviceRequest.decode(options.deviceRequest),
      credentials: options.credentials,
      treatAmbiguousMultipleDocRequestsAsAlternatives: options.treatAmbiguousMultipleDocRequestsAsAlternatives,
    })
  }

  /**
   * Create a device response for a device request, with one document per entry of `documents`.
   *
   * Throws an `UnsatisfiedDeviceRequestError` when the documents do not answer the device request
   * the way its request information asks (ISO/IEC TS 23220-4 7.2.1.3):
   *
   * - a document of an issuer its doc request does not name
   * - more than one document for a doc request with `uniqueDocSetRequired`
   * - when the device request carries use cases, a mandatory use case, or every use case, left
   *   without a document for each doc request of one of its document sets. A document counts for
   *   every doc request of its docType. Without use cases this is not checked, as the iOS DC API
   *   presents several doc requests as alternatives, see `treatAmbiguousMultipleDocRequestsAsAlternatives`
   * - a response larger than the smallest `maximumResponseSize` of the doc requests
   *
   * Elements can still be left out, and an empty `documents` declines the request.
   */
  public static async createDeviceResponseForDeviceRequest(
    options: {
      deviceRequest: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      documents: Array<DeviceResponseDocumentOptions>
    },
    context: Pick<MdocContext, 'cose' | 'crypto'>
  ) {
    return await DeviceResponse.createWithDeviceRequest(options, context)
  }
}
