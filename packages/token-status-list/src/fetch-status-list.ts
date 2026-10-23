import { isMediaType } from '@owf/identity-common'
import { SLException } from './status-list-exception'
import { MediaTypes } from './types'

export const fetchStatusList = async ({
  uri,
  customFetcher = fetch,
  acceptedFormats = ['jwt', 'cwt'],
}: {
  uri: string
  /**
   * The formats to ask for, in order of preference. If none is supplied either can be returned.
   */
  acceptedFormats?: Array<'cwt' | 'jwt'>
  customFetcher?: typeof fetch
}): Promise<string | Uint8Array> => {
  try {
    if (acceptedFormats.length === 0) {
      throw new SLException(`At least one accepted format (cwt, jwt) needs to be provided`)
    }

    // The order of the values alone expresses no preference (RFC 9110 § 12.5.1), so every format
    // after the first gets a lower quality value. Duplicates are dropped, which keeps it at 0.9.
    const acceptHeaders = Array.from(new Set(acceptedFormats)).map((format, index) => {
      const mediaType = format === 'jwt' ? MediaTypes.StatusListJwt : MediaTypes.StatusListCwt
      return index === 0 ? mediaType : `${mediaType};q=${(10 - index) / 10}`
    })

    const response = await customFetcher(uri, {
      headers: {
        Accept: acceptHeaders.join(','),
      },
    })

    if (response.status > 399 || response.status <= 199) {
      throw new Error(`Could not fetch status list, response status '${response.status}'`)
    }

    const contentType = response.headers.get('Content-Type')
    if (isMediaType(contentType, MediaTypes.StatusListJwt)) {
      return await response.text()
    } else if (isMediaType(contentType, MediaTypes.StatusListCwt)) {
      // NOTE: RN does not support .blob, use .arrayBuffer() instead
      return new Uint8Array(await response.arrayBuffer())
    }

    throw new SLException('Content type was either not provided in the response or invalid.')
  } catch (e) {
    throw new SLException(`Could not fetch either a JWT or CWT as status list. ${(e as Error).message}`)
  }
}
