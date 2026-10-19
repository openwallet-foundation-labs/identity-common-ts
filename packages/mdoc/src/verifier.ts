import type { CoseKey } from '@owf/cose'
import type { MdocContext } from './context.js'
import type { VerificationCallback } from './mdoc/check-callback.js'
import {
  DeviceRequest,
  DeviceResponse,
  type DeviceResponseVerificationResult,
  type SessionTranscript,
} from './mdoc/index.js'
import {
  type DeviceRequestMatchOptions,
  type DeviceRequestMatchResult,
  matchDeviceRequest,
} from './utils/matchDeviceRequest.js'

// biome-ignore lint/complexity/noStaticOnlyClass: part of the public API
export class Verifier {
  public static async verifyDeviceResponse(
    options: {
      deviceRequest?: DeviceRequest
      deviceRequestMatchOptions?: DeviceRequestMatchOptions
      deviceResponse: Uint8Array | DeviceResponse
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
    const deviceResponse =
      options.deviceResponse instanceof DeviceResponse
        ? options.deviceResponse
        : DeviceResponse.decode(options.deviceResponse)

    return deviceResponse.verify(options, ctx)
  }

  /**
   * Match a device response against the device request it answers, without verifying it. See
   * {@link matchDeviceRequest} for what is matched.
   *
   * `Verifier.verifyDeviceResponse` runs the same match as part of verification when a
   * `deviceRequest` is passed, reporting it through `onCheck` and returning it as
   * `deviceRequestMatch`.
   */
  public static matchDeviceRequest(options: {
    deviceRequest: Uint8Array | DeviceRequest
    deviceResponse: Uint8Array | DeviceResponse
    matchOptions?: DeviceRequestMatchOptions
    /**
     * See `issuerCertificateChains` of {@link matchDeviceRequest}: without them, no document
     * satisfies a doc request that names issuers, as the x5chain is not trusted.
     */
    issuerCertificateChains?: Array<Array<Uint8Array> | undefined>
  }): DeviceRequestMatchResult {
    return matchDeviceRequest({
      matchOptions: options.matchOptions,
      issuerCertificateChains: options.issuerCertificateChains,
      deviceRequest:
        options.deviceRequest instanceof DeviceRequest
          ? options.deviceRequest
          : DeviceRequest.decode(options.deviceRequest),
      deviceResponse:
        options.deviceResponse instanceof DeviceResponse
          ? options.deviceResponse
          : DeviceResponse.decode(options.deviceResponse),
    })
  }
}
