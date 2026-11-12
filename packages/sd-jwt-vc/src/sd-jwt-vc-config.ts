import type { FetchCallback, FetchLimits } from '@owf/identity-common'
import type { SdJwtConfig, Verifier } from '@sd-jwt/core'
import type { VctFetcher } from './sd-jwt-vc-vct'

export type StatusListFetcher = (uri: string) => Promise<string>

/** What the default `statusListFetcher` and `vctFetcher` fetch. */
export type SdJwtVcFetchType = 'statusList' | 'typeMetadata'
/** Where the status passed to a {@link StatusValidator} was read from. */
export type StatusValidatorContext = {
  /** URI of the status list. */
  uri: string
  /** Index of the credential in the status list. */
  idx: number
}

export type StatusValidator = (status: number, context: StatusValidatorContext) => Promise<void>

/** `details` of the error with code `STATUS_INVALID` that the default status validator throws. */
export type StatusInvalidErrorDetails = StatusValidatorContext & {
  /** The status of the credential, e.g. `1` for invalid (revoked) or `2` for suspended. */
  status: number
}

/** `details` of the `StatusListError` thrown when the status list token fails verification. */
export type StatusListVerificationErrorDetails = {
  /** URI of the status list. */
  uri: string
}

/**
 * Configuration for SD-JWT-VC
 *
 * @typeParam T - custom verification options that are passed to the `verifier` and the `statusVerifier`
 */
export type SdJwtVcConfig<T = unknown> = SdJwtConfig<T> & {
  // A function that fetches the status list from the uri. If not provided, the library will assume that the response is a compact JWT.
  statusListFetcher?: StatusListFetcher
  // validte the status and decide if the status is valid or not. If not provided, the code will continue if it is 0, otherwise it will throw an error.
  // To have safeVerify report an invalid status as STATUS_INVALID, throw an SdJwtError with the code 'STATUS_INVALID'.
  statusValidator?: StatusValidator
  // a function that fetches the type metadata format from the uri. If not provided, the library will assume that the response is a TypeMetadataFormat. Caching has to be implemented in this function. If the integrity value is passed, it to be validated according to https://www.w3.org/TR/SRI/
  vctFetcher?: VctFetcher
  // a function that verifies the signature of the status list JWT. It gets the verification options. If not provided, the verifier is used.
  statusVerifier?: Verifier<T>
  // maximum size in bytes the status list may inflate to. If not provided, it will default to 16 MiB, 2^27 statuses at 1 bit per status.
  maxStatusListDecompressedBytes?: number
  // if set to true, it will load the metadata format based on the vct value. If not provided, it will default to false.
  loadTypeMetadataFormat?: boolean
  // timeout value in milliseconds when to abort the fetch request. If not provided, it will default to 10000.
  timeout?: number
  // the fetch of the default statusListFetcher and vctFetcher, which gets { type: 'statusList' } or { type: 'typeMetadata' } as its third argument. If not provided, the global fetch is used.
  fetch?: FetchCallback<SdJwtVcFetchType>
  // maximum sizes of the responses of the default statusListFetcher and vctFetcher (see FetchLimits of @owf/identity-common). If not provided, 16 MiB for a status list and 1 MiB for type metadata.
  fetchLimits?: FetchLimits<SdJwtVcFetchType>
  // maximum depth of extends chain to resolve. If not provided, it will default to 5. Set to -1 to not limit the vct extends depth.
  maxVctExtendsDepth?: number
}
