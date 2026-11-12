import { bytesToString, createAcceptHeader, isMediaType, readResponseBodyAtMost } from '@owf/identity-common'
import { StatusListError } from './status-list-error'
import { StatusListMediaTypes } from './types'

/**
 * The default maximum size of a status list response. The largest list of Token Status List draft 16 Appendix B,
 * 100 million statuses of which half are revoked, compresses to 11.9 MB, about 15.1 MiB as a JWT.
 */
const DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024

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
      return bytesToString(await readResponseBodyAtMost(response, maxResponseBytes))
    } else if (isMediaType(contentType, StatusListMediaTypes.StatusListCwt)) {
      return await readResponseBodyAtMost(response, maxResponseBytes)
    }

    throw new StatusListError('Content type was either not provided in the response or invalid.')
  } catch (e) {
    throw new StatusListError(`Could not fetch either a JWT or CWT as status list. ${(e as Error).message}`)
  }
}
