import type z from 'zod'
import { ContentType, isResponseContentType } from './content-type'
import { FetchError } from './error/FetchError'
import { InvalidFetchResponseError } from './error/InvalidFetchResponseError'
import { type Fetch, Headers, URLSearchParams } from './globals'

/**
 * A type utility which represents the function returned
 * from createZodFetcher
 */
export type ZodFetcher = <Schema extends z.ZodTypeAny>(
  schema: Schema,
  expectedContentType: ContentType | ContentType[],
  ...args: Parameters<Fetch>
) => Promise<{ response: Awaited<ReturnType<Fetch>>; result?: z.ZodSafeParseResult<z.infer<Schema>> }>

/**
 * The default fetcher used by createZodFetcher when no
 * fetcher is provided.
 */
// biome-ignore lint/style/noRestrictedGlobals: this is the only place where we use the global
const defaultFetcher = fetch

export function createFetcher(fetcher = defaultFetcher): Fetch {
  return (input, init, ...args) => {
    return fetcher(
      input,
      init
        ? {
            ...init,
            // React Native does not seem to handle the toString(). This is hard to catch when running
            // tests in Node.JS where this does work correctly. so we handle it here.
            body: init.body instanceof URLSearchParams ? init.body.toString() : init.body,
          }
        : undefined,
      ...args
    ).catch((error) => {
      throw new FetchError(`Unknown error occurred during fetch to '${input}'`, { cause: error })
    })
  }
}

/**
 * Creates a `fetchWithZod` function that takes in a schema of
 * the expected response, and the arguments to the fetcher
 * you provided. The expected content types are sent as the
 * `Accept` header, unless the request already has one. The
 * order of the expected content types is the order of preference,
 * expressed with decreasing `q` values.
 *
 * @example
 *
 * const fetchWithZod = createZodFetcher((url) => {
 *   return fetch(url).then((res) => res.json());
 * });
 *
 * const response = await fetchWithZod(
 *   z.object({
 *     hello: z.string(),
 *   }),
 *   "https://example.com",
 * );
 */
export function createZodFetcher(fetcher?: Fetch): ZodFetcher {
  return async (schema, expectedContentType, input, init) => {
    const expectedContentTypeArray = Array.isArray(expectedContentType) ? expectedContentType : [expectedContentType]

    // Ask for the expected content types in order of preference, unless the caller already set an Accept header
    const headers = new Headers(init?.headers)
    if (!headers.has('Accept')) {
      headers.set(
        'Accept',
        expectedContentTypeArray
          .map((contentType, index) =>
            index === 0 ? contentType : `${contentType};q=${Math.max(0.1, 1 - index / 10).toFixed(1)}`
          )
          .join(', ')
      )
    }

    const response = await createFetcher(fetcher)(input, { ...init, headers })

    if (response.ok && !isResponseContentType(expectedContentTypeArray, response)) {
      throw new InvalidFetchResponseError(
        `Expected response to match content type ${expectedContentTypeArray.join(' | ')}, but received '${response.headers.get('Content-Type')}'`,
        await response.clone().text(),
        response
      )
    }

    if (isResponseContentType([ContentType.OAuthAuthorizationRequestJwt, ContentType.Jwt], response)) {
      return {
        response,
        result: response.ok ? schema.safeParse(await response.text()) : undefined,
      }
    }

    return {
      response,
      result: response.ok ? schema.safeParse(await response.json()) : undefined,
    }
  }
}
