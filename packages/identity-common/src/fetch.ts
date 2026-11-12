import { createAcceptHeader, isMediaType } from './content-type'
import { IdentityCommonError } from './identity-common-error'
import { readResponseBodyAtMost } from './response-body'

/**
 * What is fetched, passed to a {@link FetchCallback} as its third argument. Each library defines the types it fetches,
 * e.g. `'statusList'`, so a callback passed to a library only gets the types of that library.
 */
export interface FetchContext<Type extends string = string> {
  type: Type
}

/**
 * Fetches a resource for a library of this repository, which reads the body of the response within the limit of
 * {@link FetchLimits}, so the callback does not have to limit it. `context` says what is fetched, so the callback
 * can apply its own policy per type, such as a timeout or a cache.
 *
 * The global `fetch` satisfies this, as it ignores the third argument. In React Native without Expo, use a fetch that
 * streams the body, such as the one of Expo (`expo/fetch`) or `react-native-nitro-fetch`: the body of a fetch without
 * a body stream is read whole before its size can be checked.
 */
export type FetchCallback<Type extends string = string> = (
  input: string,
  init: RequestInit,
  context: FetchContext<Type>
) => Promise<Response>

/**
 * The maximum sizes of the response bodies a library reads. The limit for a type is `maxResponseBytesByType[type]`,
 * else `maxResponseBytes`, else the default of the library for the type, else 10 MiB.
 */
export interface FetchLimits<Type extends string = string> {
  /** The maximum size in bytes of every response body, unless `maxResponseBytesByType` has one for its type. */
  maxResponseBytes?: number
  /** The maximum size in bytes of the response body per type. */
  maxResponseBytesByType?: Partial<Record<Type, number>>
}

/** How a library fetches. */
export interface FetchOptions<Type extends string = string> {
  /** Defaults to the global `fetch`. */
  fetch?: FetchCallback<Type>
  fetchLimits?: FetchLimits<Type>
}

/** A request of {@link fetchWithLimits}. */
export interface FetchRequest<Type extends string = string> {
  type: Type
  url: string
  init?: RequestInit
  /** The media types to ask for, in order of preference. Sent as `Accept`, unless `init` sets that header. */
  accept?: string | ReadonlyArray<string>
  /** The limit of the library for `type`, when `fetchLimits` sets none. 10 MiB by default. */
  defaultMaxResponseBytes?: number
}

/** The limit when neither the caller nor the library sets one, as the agent default of Credo. */
const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024

/**
 * A copy of `init`. Not `new Headers(init)`, which can drop headers of a `Headers` of another implementation, e.g. of
 * a polyfill that replaced the global after it was created.
 */
function copyHeaders(init: HeadersInit | undefined): Headers {
  if (init === undefined || Array.isArray(init) || typeof (init as Headers).forEach !== 'function') {
    return new Headers(init)
  }

  const headers = new Headers()
  ;(init as Headers).forEach((value, name) => {
    headers.append(name, value)
  })
  return headers
}

/** Resolved on every call, so a fetch that is set or replaced after this module is loaded is used. */
const globalFetch: FetchCallback = (input, init) => globalThis.fetch(input, init)

/**
 * Fetches `url`, and reads the body of the response within the limit of `fetchLimits` for `type`.
 *
 * @returns The response, with its body held in memory, so it can be read and cloned as often as needed.
 * @throws IdentityCommonError if the limit is not a number of 0 or more, or the body is larger. An error of `fetch`
 *   is passed on.
 */
export async function fetchWithLimits<Type extends string>(
  options: FetchOptions<Type>,
  request: FetchRequest<Type>
): Promise<Response> {
  return (await fetchBody(options, request)).response
}

/** The result of {@link fetchAndParse}. */
export type FetchAndParseResult<T> = { response: Response; data: T } | { response: Response; data?: undefined }

/**
 * Fetches `url` as {@link fetchWithLimits} does, and parses the body of a response with a 2xx status with `parse`,
 * e.g. with a zod schema or into a class instance.
 *
 * @returns The response, and `data` if its status is 2xx. Without `data`, the caller decides what the status means,
 *   e.g. reads an error response from the body, which may be of any media type.
 * @throws IdentityCommonError as {@link fetchWithLimits} does, and if `accept` is given and a response with a 2xx
 *   status is not of one of its media types. Errors of `fetch` and `parse` are passed on.
 */
export async function fetchAndParse<T, Type extends string>(
  options: FetchOptions<Type>,
  {
    parse,
    ...request
  }: FetchRequest<Type> & { parse: (body: Uint8Array<ArrayBuffer>, response: Response) => T | Promise<T> }
): Promise<FetchAndParseResult<T>> {
  const { response, body } = await fetchBody(options, request)
  if (!response.ok) return { response }

  const contentType = response.headers.get('Content-Type')
  if (request.accept !== undefined && !isMediaType(contentType, request.accept)) {
    // Not with the body, which may come from an internal endpoint
    const accept = typeof request.accept === 'string' ? [request.accept] : request.accept
    throw new IdentityCommonError(
      `Expected response to match content type ${accept.join(' | ')}, but received '${contentType}'`
    )
  }

  return { response, data: await parse(body, response) }
}

async function fetchBody<Type extends string>(
  { fetch = globalFetch, fetchLimits }: FetchOptions<Type>,
  { type, url, init, accept, defaultMaxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES }: FetchRequest<Type>
): Promise<{ response: Response; body: Uint8Array<ArrayBuffer> }> {
  const maxResponseBytes =
    fetchLimits?.maxResponseBytesByType?.[type] ?? fetchLimits?.maxResponseBytes ?? defaultMaxResponseBytes
  // Before the request is made, rather than once its body is read
  if (Number.isNaN(maxResponseBytes) || maxResponseBytes < 0) {
    throw new IdentityCommonError(
      `The maximum size of a ${type} response must be a number of 0 or more, but is ${maxResponseBytes}`
    )
  }

  const headers = copyHeaders(init?.headers)
  if (accept !== undefined && !headers.has('Accept')) {
    headers.set('Accept', createAcceptHeader(typeof accept === 'string' ? [accept] : accept))
  }

  const fetched = await fetch(url, { ...init, headers }, { type })
  const body = await readResponseBodyAtMost(fetched, maxResponseBytes)

  // The body is decoded, so these headers no longer describe it
  const bufferedHeaders = copyHeaders(fetched.headers)
  bufferedHeaders.delete('Content-Encoding')
  bufferedHeaders.delete('Content-Length')

  // A status such as 204 cannot have a body, not even an empty one
  const response = new Response(body.length > 0 ? body : null, {
    status: fetched.status,
    statusText: fetched.statusText,
    headers: bufferedHeaders,
  })
  // The constructor cannot set these, and callers read them, e.g. to follow a redirect
  Object.defineProperties(response, {
    url: { value: fetched.url },
    redirected: { value: fetched.redirected },
  })

  return { response, body }
}
