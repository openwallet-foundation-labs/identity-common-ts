import { bytesToString, createAcceptHeader, isMediaType } from '@owf/identity-common'
import { StatusListError } from './status-list-error'
import { StatusListMediaTypes } from './types'

/**
 * The default maximum size of a status list response. The largest list of Token Status List draft 16 Appendix B,
 * 100 million statuses of which half are revoked, compresses to 11.9 MB, about 15.1 MiB as a JWT.
 */
const DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024

/**
 * Read the body of `response`, but stop with an error once it is larger than `maxBytes`, so that a large response is
 * not read into memory whole.
 */
async function readBodyAtMost(response: Response, maxBytes: number): Promise<Uint8Array> {
  const tooLarge = () => new StatusListError(`The response is larger than the maximum of ${maxBytes} bytes`)

  // Rejected before the body is read. The header is optional, so the body is counted too. Negated, so that a
  // `maxBytes` of NaN rejects every response rather than none.
  const contentLength = response.headers.get('Content-Length')
  if (contentLength !== null && !(Number(contentLength) <= maxBytes)) {
    response.body?.cancel().catch(() => {})
    throw tooLarge()
  }

  // The fetch of React Native has no body stream, so the body is read whole and checked afterwards
  if (!response.body) {
    const body = new Uint8Array(await response.arrayBuffer())
    if (!(body.length <= maxBytes)) throw tooLarge()
    return body
  }

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let length = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    length += value.length
    if (!(length <= maxBytes)) {
      reader.cancel().catch(() => {})
      throw tooLarge()
    }
    chunks.push(value)
  }

  // Not `concatBytes(...chunks)`: a body of many small chunks would exceed the maximum number of arguments
  const body = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.length
  }
  return body
}

export const fetchStatusList = async ({
  uri,
  customFetcher = fetch,
  acceptedFormats = ['jwt', 'cwt'],
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
}: {
  uri: string
  /**
   * The formats to ask for, in order of preference. If none is supplied either can be returned.
   */
  acceptedFormats?: Array<'cwt' | 'jwt'>
  customFetcher?: typeof fetch
  /**
   * The maximum size in bytes of the response body, 16 MiB by default. A larger response is rejected, without
   * reading more of it than the maximum where the platform streams the body.
   */
  maxResponseBytes?: number
}): Promise<string | Uint8Array> => {
  try {
    if (acceptedFormats.length === 0) {
      throw new StatusListError(`At least one accepted format (cwt, jwt) needs to be provided`)
    }

    const acceptHeader = createAcceptHeader(
      acceptedFormats.map((format) =>
        format === 'jwt' ? StatusListMediaTypes.StatusListJwt : StatusListMediaTypes.StatusListCwt
      )
    )

    const response = await customFetcher(uri, {
      headers: {
        Accept: acceptHeader,
      },
    })

    if (response.status > 399 || response.status <= 199) {
      throw new Error(`Could not fetch status list, response status '${response.status}'`)
    }

    const contentType = response.headers.get('Content-Type')
    if (isMediaType(contentType, StatusListMediaTypes.StatusListJwt)) {
      return bytesToString(await readBodyAtMost(response, maxResponseBytes))
    } else if (isMediaType(contentType, StatusListMediaTypes.StatusListCwt)) {
      return await readBodyAtMost(response, maxResponseBytes)
    }

    throw new StatusListError('Content type was either not provided in the response or invalid.')
  } catch (e) {
    throw new StatusListError(`Could not fetch either a JWT or CWT as status list. ${(e as Error).message}`)
  }
}
