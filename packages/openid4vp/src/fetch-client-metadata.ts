import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { createZodFetcher, type Fetch } from '@openid4vc/utils'
import { CommonMediaTypes } from '@owf/identity-common'
import { type ClientMetadata, zClientMetadata } from './models/z-client-metadata'

export async function fetchClientMetadata(options: {
  clientMetadataUri: string
  fetch?: Fetch
}): Promise<ClientMetadata> {
  const { fetch, clientMetadataUri } = options
  const fetcher = createZodFetcher(fetch)

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
