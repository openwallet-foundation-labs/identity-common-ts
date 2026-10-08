import type { SDJWTConfig, Verifier } from '@sd-jwt/core'
import type { VCTFetcher } from './sd-jwt-vc-vct'

export type StatusListFetcher = (uri: string) => Promise<string>
/** Where the status passed to a {@link StatusValidator} was read from. */
export type StatusValidatorContext = {
  /** URI of the status list. */
  uri: string
  /** Index of the credential in the status list. */
  idx: number
}

export type StatusValidator = (status: number, context: StatusValidatorContext) => Promise<void>

/** `details` of the exception with code `STATUS_INVALID` that the default status validator throws. */
export type StatusInvalidErrorDetails = StatusValidatorContext & {
  /** The status of the credential, e.g. `1` for invalid (revoked) or `2` for suspended. */
  status: number
}

/** `details` of the `SLException` thrown when the status list token fails verification. */
export type StatusListVerificationErrorDetails = {
  /** URI of the status list. */
  uri: string
}

/**
 * Configuration for SD-JWT-VC
 *
 * @typeParam T - custom verification options that are passed to the `verifier` and the `statusVerifier`
 */
export type SDJWTVCConfig<T = unknown> = SDJWTConfig<T> & {
  // A function that fetches the status list from the uri. If not provided, the library will assume that the response is a compact JWT.
  statusListFetcher?: StatusListFetcher
  // validte the status and decide if the status is valid or not. If not provided, the code will continue if it is 0, otherwise it will throw an error.
  // To have safeVerify report an invalid status as STATUS_INVALID, throw an SDJWTException with the code 'STATUS_INVALID'.
  statusValidator?: StatusValidator
  // a function that fetches the type metadata format from the uri. If not provided, the library will assume that the response is a TypeMetadataFormat. Caching has to be implemented in this function. If the integrity value is passed, it to be validated according to https://www.w3.org/TR/SRI/
  vctFetcher?: VCTFetcher
  // a function that verifies the signature of the status list JWT. It gets the verification options. If not provided, the verifier is used.
  statusVerifier?: Verifier<T>
  // if set to true, it will load the metadata format based on the vct value. If not provided, it will default to false.
  loadTypeMetadataFormat?: boolean
  // timeout value in milliseconds when to abort the fetch request. If not provided, it will default to 10000.
  timeout?: number
  // maximum depth of extends chain to resolve. If not provided, it will default to 5. Set to -1 to not limit the vct extends depth.
  maxVctExtendsDepth?: number
}
