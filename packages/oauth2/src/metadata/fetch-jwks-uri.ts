import { createZodFetcher, type Fetch, InvalidFetchResponseError } from '@openid4vc/utils'
import { CommonMediaTypes, parseWithErrorHandling, ValidationError } from '@owf/identity-common'
import { type JwkSet, zJwkSet } from '@owf/jose'
import type { CallbackContext } from '../callbacks'

/**
 * Fetch JWKs from a provided JWKs URI.
 *
 * If a `getJwks` callback is provided and returns a JWK Set for the `jwksUrl`, that JWK Set is
 * returned and no request is performed.
 *
 * Returns validated metadata if successful response
 * Throws error otherwise
 *
 * @throws {ValidationError} if successful response but validation of response failed
 * @throws {InvalidFetchResponseError} if unsuccessful response
 */
export async function fetchJwks(
  jwksUrl: string,
  fetchOrCallbacks?: Fetch | Pick<CallbackContext, 'fetch' | 'fetchLimits' | 'getJwks'>
): Promise<JwkSet> {
  const callbacks = typeof fetchOrCallbacks === 'function' ? { fetch: fetchOrCallbacks } : fetchOrCallbacks
  const providedJwks = await callbacks?.getJwks?.(jwksUrl)
  if (providedJwks) {
    // Validated the same way as JWKs retrieved from the jwks_uri
    return parseWithErrorHandling(
      zJwkSet,
      providedJwks,
      `Validation of JWKs provided by the 'getJwks' callback for jwks_uri '${jwksUrl}' failed`
    )
  }

  const fetcher = createZodFetcher(callbacks, 'jwks')

  const { result, response } = await fetcher(zJwkSet, [CommonMediaTypes.JwkSet, CommonMediaTypes.Json], jwksUrl)
  if (!response.ok) {
    throw new InvalidFetchResponseError(
      `Fetching JWKs from jwks_uri '${jwksUrl}' resulted in an unsuccessful response with status code '${response.status}'.`,
      await response.clone().text(),
      response
    )
  }

  if (!result?.success) {
    throw new ValidationError(`Validation of JWKs from jwks_uri '${jwksUrl}' failed`, result?.issues ?? [])
  }

  return result.data
}
