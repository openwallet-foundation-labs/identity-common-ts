import { MediaTypes } from './types'

export const fetchStatusList = async ({
  uri,
  customFetcher = fetch,
  requiredFormat,
}: {
  uri: string
  /**
   *
   * If none is supplied either can be returned
   *
   */
  requiredFormat?: 'cwt' | 'jwt'
  customFetcher?: typeof fetch
}): Promise<string | Uint8Array> => {
  if (requiredFormat === 'cwt') {
    return fetchCwtStatusList(uri, customFetcher)
  }
  if (requiredFormat === 'jwt') {
    return fetchJwtStatusList(uri, customFetcher)
  }
  try {
    return fetchJwtStatusList(uri, customFetcher)
  } catch {
    try {
      return fetchCwtStatusList(uri, customFetcher)
    } catch {
      throw new Error('Could not fetch either a JWT or CWT as status list')
    }
  }
}

const fetchJwtStatusList = async (uri: string, customFetcher: typeof fetch) => {
  const response = await customFetcher(uri, {
    headers: {
      Accept: MediaTypes.StatusListJwt,
    },
  })

  const token = await response.text()

  return token
}

const fetchCwtStatusList = async (uri: string, customFetcher: typeof fetch) => {
  const response = await customFetcher(uri, {
    headers: {
      Accept: MediaTypes.StatusListCwt,
    },
  })

  const token = await (await response.blob()).bytes()

  return token
}
