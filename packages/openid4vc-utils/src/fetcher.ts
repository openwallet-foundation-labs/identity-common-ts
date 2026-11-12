import {
  bytesToString,
  CommonMediaTypes,
  type FetchCallback,
  type FetchLimits,
  type FetchOptions,
  type FetchType,
  fetchAndParse,
  fetchWithLimits,
  isMediaType,
  parseWithSchema,
  type SchemaParseResult,
} from '@owf/identity-common'
import type z from 'zod'
import { FetchError } from './error/FetchError'
import { InvalidFetchResponseError } from './error/InvalidFetchResponseError'
import { type FetchRequestInit, type FetchResponse, URLSearchParams } from './globals'

/**
 * The fetch the packages take. The global `fetch` satisfies it, and it gets what is fetched as its third argument,
 * `{ type }`. The packages read the body of a response within {@link FetchLimits}, so it does not have to limit it.
 */
export type Fetch = FetchCallback

/** The `fetch` and `fetchLimits` of the callbacks, through which a request is made. */
export type FetchCallbacks = { fetch?: Fetch; fetchLimits?: FetchLimits }

/**
 * A type utility which represents the function returned
 * from createZodFetcher
 */
export type ZodFetcher = <Schema extends z.ZodTypeAny>(
  schema: Schema,
  expectedContentType: string | string[],
  input: string,
  init?: FetchRequestInit
) => Promise<{ response: FetchResponse; result?: SchemaParseResult<z.infer<Schema>> }>

/**
 * The default fetcher used by createFetcher when no fetcher is provided. Resolved on every call, so a fetch that is
 * set or replaced after this module is loaded is used.
 */
const defaultFetcher: Fetch = (input, init) => globalThis.fetch(input, init)

/** The options of the fetch layer, with the errors of `fetch` wrapped in a `FetchError`. */
function fetchOptions({ fetch = defaultFetcher, fetchLimits }: FetchCallbacks = {}): FetchOptions {
  return {
    fetchLimits,
    fetch: async (input, init, context) => {
      try {
        return await fetch(input, init, context)
      } catch (error) {
        throw new FetchError(`Unknown error occurred during fetch to '${input}'`, { cause: error as Error })
      }
    },
  }
}

// React Native does not seem to handle the toString(). This is hard to catch when running
// tests in Node.JS where this does work correctly. so we handle it here.
const requestInit = (init?: FetchRequestInit): FetchRequestInit | undefined =>
  init && { ...init, body: init.body instanceof URLSearchParams ? init.body.toString() : init.body }

/**
 * Creates a fetch for requests of `type`, which reads the body of the response within the limit of
 * `callbacks.fetchLimits` for `type`, and returns a response that holds it.
 *
 * @throws FetchError if `callbacks.fetch` fails, and the `IdentityCommonError` of `@owf/identity-common` if the
 *   response is larger than its limit.
 */
export function createFetcher(
  callbacks: FetchCallbacks | undefined,
  type: FetchType
): (input: string, init?: FetchRequestInit) => Promise<FetchResponse> {
  return (input, init) => fetchWithLimits(fetchOptions(callbacks), { type, url: input, init: requestInit(init) })
}

/**
 * Creates a `fetchWithZod` function for requests of `type`, that takes in a schema of the expected response, and
 * the arguments of the request. The expected content types are sent as the `Accept` header, unless the request
 * already has one. The order of the expected content types is the order of preference, expressed with decreasing
 * `q` values. The body of the response is read within the limit of `callbacks.fetchLimits` for `type`.
 *
 * @throws IdentityCommonError (from `@owf/identity-common`) if a response with a 2xx status is not of one of the
 *   expected content types, or is larger than its limit.
 *
 * @example
 *
 * const fetchWithZod = createZodFetcher(callbacks, 'jwks')
 *
 * const { response, result } = await fetchWithZod(zJwkSet, CommonMediaTypes.JwkSet, 'https://example.com/jwks')
 */
export function createZodFetcher(callbacks: FetchCallbacks | undefined, type: FetchType): ZodFetcher {
  return async (schema, expectedContentType, input, init) => {
    const expectedContentTypeArray = Array.isArray(expectedContentType) ? expectedContentType : [expectedContentType]

    const { response, data } = await fetchAndParse(fetchOptions(callbacks), {
      type,
      url: input,
      init: requestInit(init),
      accept: expectedContentTypeArray,
      parse: (body, response) => {
        const text = bytesToString(body, { stripByteOrderMark: true })
        // A compact JWT is text, not JSON (RFC 7519 Section 1)
        return parseWithSchema(
          schema,
          isMediaType(response.headers.get('Content-Type'), CommonMediaTypes.Jwt) ? text : parseJson(text, response)
        )
      },
    })

    return { response, result: data }
  }
}

/**
 * The JSON of the response body. Not `response.json()`, as its `SyntaxError` quotes the start of the body, which may
 * come from an internal endpoint.
 */
function parseJson(text: string, response: FetchResponse): unknown {
  try {
    return JSON.parse(text)
  } catch {
    throw new InvalidFetchResponseError(
      'Expected the response body to be JSON, but it could not be parsed',
      text,
      response
    )
  }
}
