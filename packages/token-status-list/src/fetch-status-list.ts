import { SLException } from './status-list-exception'
import { MediaTypes } from './types'

export const fetchStatusList = async ({
  uri,
  customFetcher = fetch,
  acceptedFormats = ['jwt', 'cwt'],
}: {
  uri: string
  /**
   *
   * If none is supplied either can be returned
   *
   */
  acceptedFormats?: Array<'cwt' | 'jwt'>
  customFetcher?: typeof fetch
}): Promise<string | Uint8Array> => {
  try {
    if (acceptedFormats.length === 0) {
      throw new SLException(`At least one accepted format (cwt, jwt) needs to be provided`)
    }

    const acceptHeaders = acceptedFormats.map((format) =>
      format === 'jwt' ? MediaTypes.StatusListJwt : MediaTypes.StatusListCwt
    )

    const response = await customFetcher(uri, {
      headers: {
        Accept: acceptHeaders.join(','),
      },
    })

    if (response.status > 399 || response.status <= 199) {
      throw new Error(`Could not fetch status list, response status '${response.status}'`)
    }

    const contentType = response.headers.get('Content-type')
    if (contentType === MediaTypes.StatusListJwt) {
      return await response.text()
    } else if (contentType === MediaTypes.StatusListCwt) {
      return await (await response.blob()).bytes()
    }

    throw new SLException('Content type was either not provided in the response or invalid.')
  } catch (e) {
    throw new SLException(`Could not fetch either a JWT or CWT as status list. ${(e as Error).message}`)
  }
}
