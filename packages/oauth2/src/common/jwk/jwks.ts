import { extractJwkFromJwkSet, type Jwk, type JwkSet, isJwkInSet as joseIsJwkInSet } from '@owf/jose'
import type { CallbackContext } from '../../callbacks'
import { Oauth2Error } from '../../error/Oauth2Error'

interface ExtractJwkFromJwksForJwtOptions {
  kid?: string
  use: 'enc' | 'sig'

  /**
   * The JWKs
   */
  jwks: JwkSet
}

/**
 * Selects the key to use from a JWK Set: the key with the given `kid`, or the only key that is
 * usable for `use` when no `kid` was given.
 */
export function extractJwkFromJwksForJwt(options: ExtractJwkFromJwksForJwtOptions): Jwk {
  try {
    return extractJwkFromJwkSet(options)
  } catch (error) {
    throw new Oauth2Error(error instanceof Error ? error.message : 'Unable to extract jwk from jwks', { cause: error })
  }
}

/**
 * Whether `jwk` is one of `jwks`, compared by JWK thumbprint.
 */
export async function isJwkInSet({
  jwk,
  jwks,
  callbacks,
}: {
  jwk: Jwk
  jwks: Jwk[]
  callbacks: Pick<CallbackContext, 'hash'>
}) {
  return await joseIsJwkInSet({ jwk, jwks, hashCallback: callbacks.hash })
}
