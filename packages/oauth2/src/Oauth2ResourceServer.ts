import { type VerifyResourceRequestOptions, verifyResourceRequest } from '.'
import type { CallbackContext } from './callbacks'

export interface Oauth2ResourceServerOptions {
  /**
   * Callbacks required for the oauth2 resource server
   */
  callbacks: Pick<CallbackContext, 'verifyJws' | 'hash' | 'clientAuthentication' | 'fetch' | 'fetchLimits' | 'getJwks'>

  /**
   * Default allowed clock skew in seconds for the `exp`, `nbf` and `iat` checks of access tokens and
   * DPoP proofs. A per-call `allowedSkewInSeconds` takes precedence, including `0`.
   *
   * @default 30
   */
  allowedSkewInSeconds?: number
}

export class Oauth2ResourceServer {
  public constructor(private options: Oauth2ResourceServerOptions) {}

  public async verifyResourceRequest(options: Omit<VerifyResourceRequestOptions, 'callbacks'>) {
    return verifyResourceRequest({
      callbacks: this.options.callbacks,
      ...options,
      allowedSkewInSeconds: options.allowedSkewInSeconds ?? this.options.allowedSkewInSeconds,
    })
  }
}
