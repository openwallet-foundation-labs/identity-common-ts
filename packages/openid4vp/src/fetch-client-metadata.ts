import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { createZodFetcher, type Fetch, type Openid4vcFetchType } from '@openid4vc/utils'
import { CommonMediaTypes, type FetchLimits } from '@owf/identity-common'
import { type ClientMetadata, zClientMetadata } from './models/z-client-metadata'

export async function fetchClientMetadata(options: {
  clientMetadataUri: string
  fetch?: Fetch
  /** The maximum size of the response, 10 MiB by default (see `FetchLimits` of `@owf/identity-common`) */
  fetchLimits?: FetchLimits<Openid4vcFetchType>
}): Promise<ClientMetadata> {
  const { clientMetadataUri } = options
  const fetcher = createZodFetcher(options, 'clientMetadata')

  const { result, response } = await fetcher(zClientMetadata, CommonMediaTypes.Json, clientMetadataUri, {
    method: 'GET',
  })

  if (!response.ok) {
    throw new Oauth2ServerErrorResponseError({
      error_description: `Fetching client metadata from '${clientMetadataUri}' failed with status code '${response.status}'.`,
      error: Oauth2ErrorCodes.InvalidRequestUri,
    })
  }

  if (!result?.success) {
    throw new Oauth2ServerErrorResponseError({
      error_description: `Parsing client metadata from '${clientMetadataUri}' failed.`,
      error: Oauth2ErrorCodes.InvalidRequestObject,
    })
  }

  return result.data
}
