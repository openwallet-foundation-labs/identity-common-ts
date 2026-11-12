import { bytesToString, type FetchCallback, type FetchLimits, fetchWithLimits, isMediaType } from '@owf/identity-common'
import { StatusListError } from './status-list-error'
import { StatusListMediaTypes } from './types'

/**
 * The default maximum size of a status list response. The largest list of Token Status List draft 16 Appendix B,
 * 100 million statuses of which half are revoked, compresses to 11.9 MB, about 15.1 MiB as a JWT.
 */
const DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024

export const fetchStatusList = async ({
  uri,
  customFetcher,
  fetchLimits,
  acceptedFormats = ['jwt', 'cwt'],
}: {
  uri: string
  /**
   * The formats to ask for, in order of preference. If none is supplied either can be returned.
   */
  acceptedFormats?: Array<'cwt' | 'jwt'>
  /** Defaults to the global `fetch`. It gets `{ type: 'statusList' }` as its third argument. */
  customFetcher?: FetchCallback<'statusList'>
  /**
   * The maximum size of the response, 16 MiB for a status list by default. A larger response is rejected, without
   * reading more of it than the maximum where the platform streams the body.
   */
  fetchLimits?: FetchLimits<'statusList'>
}): Promise<string | Uint8Array> => {
  try {
    if (acceptedFormats.length === 0) {
      throw new StatusListError(`At least one accepted format (cwt, jwt) needs to be provided`)
    }

    const response = await fetchWithLimits(
      { fetch: customFetcher, fetchLimits },
      {
        type: 'statusList',
        url: uri,
        defaultMaxResponseBytes: DEFAULT_MAX_RESPONSE_BYTES,
        accept: acceptedFormats.map((format) =>
          format === 'jwt' ? StatusListMediaTypes.StatusListJwt : StatusListMediaTypes.StatusListCwt
        ),
      }
    )

    if (response.status > 399 || response.status <= 199) {
      throw new Error(`Could not fetch status list, response status '${response.status}'`)
    }

    const contentType = response.headers.get('Content-Type')
    if (isMediaType(contentType, StatusListMediaTypes.StatusListJwt)) {
      return bytesToString(new Uint8Array(await response.arrayBuffer()))
    } else if (isMediaType(contentType, StatusListMediaTypes.StatusListCwt)) {
      return new Uint8Array(await response.arrayBuffer())
    }

    throw new StatusListError('Content type was either not provided in the response or invalid.')
  } catch (e) {
    throw new StatusListError(`Could not fetch either a JWT or CWT as status list. ${(e as Error).message}`)
  }
}
