export { arrayEqualsIgnoreOrder } from './array'
export { getGlobalConfig, type Oid4vcTsConfig, setGlobalConfig } from './config'
export { addSecondsToDate } from './date'
export { InvalidFetchResponseError } from './error/InvalidFetchResponseError'
export { JsonParseError } from './error/JsonParseError'
export { Openid4vcBaseError } from './error/Openid4vcBaseError'
export { createFetcher, createZodFetcher, type ZodFetcher } from './fetcher'
export {
  type Fetch,
  type FetchHeaders,
  type FetchRequestInit,
  type FetchResponse,
  Headers,
  URL,
  URLSearchParams,
} from './globals'
export { isObject, mergeDeep } from './object'
export {
  type InferOutputUnion,
  parseIfJson,
  stringToJsonWithErrorHandling,
} from './parse'
export { joinUriParts } from './path'
export type { NonEmptyArray, Optional, Simplify, StringWithAutoCompletion } from './type'
export { getQueryParams, objectToQueryParams } from './url'
export {
  type HttpMethod,
  zDataUrl,
  zHttpMethod,
  zHttpsUrl,
  zInteger,
  zIs,
  zStringToJson,
} from './validation'
export {
  encodeWwwAuthenticateHeader,
  parseWwwAuthenticateHeader,
  type WwwAuthenticateHeaderChallenge,
} from './www-authenticate'
