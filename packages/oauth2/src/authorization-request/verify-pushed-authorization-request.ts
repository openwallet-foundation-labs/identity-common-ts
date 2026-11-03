import type { JwsSigner } from '@owf/jose'
import { type VerifiedJarRequest, verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import {
  type VerifyAuthorizationRequestOptions,
  type VerifyAuthorizationRequestReturn,
  verifyAuthorizationRequest,
} from './verify-authorization-request'

export interface VerifyPushedAuthorizationRequestReturn extends VerifyAuthorizationRequestReturn {
  /**
   * The verified JAR request, if `authorizationRequestJwt` was provided
   */
  jar?: VerifiedJarRequest
}

export interface VerifyPushedAuthorizationRequestOptions extends VerifyAuthorizationRequestOptions {
  /**
   * The authorization request JWT to verify. If this value was returned from `parsePushedAuthorizationRequest`
   * you MUST provide this value to ensure the JWT is verified.
   */
  authorizationRequestJwt?: {
    jwt: string
    signer: JwsSigner
  }

  /**
   * Allowed clock skew in seconds for the `exp`, `nbf` and `iat` checks of the request object, the DPoP
   * proof and the client attestation. A `dpop.allowedSkewInSeconds` or `clientAttestation.allowedSkewInSeconds`
   * takes precedence for that one.
   *
   * @default 30
   */
  allowedSkewInSeconds?: number
}

export async function verifyPushedAuthorizationRequest(
  options: VerifyPushedAuthorizationRequestOptions
): Promise<VerifyPushedAuthorizationRequestReturn> {
  let jar: VerifiedJarRequest | undefined
  if (options.authorizationRequestJwt) {
    jar = await verifyJarRequest({
      authorizationRequestJwt: options.authorizationRequestJwt.jwt,
      jarRequestParams: options.authorizationRequest,
      callbacks: options.callbacks,
      jwtSigner: options.authorizationRequestJwt.signer,
      now: options.now,
      allowedSkewInSeconds: options.allowedSkewInSeconds,
    })
  }

  const withSkew = <T extends { allowedSkewInSeconds?: number }>(nested: T | undefined) =>
    nested && { ...nested, allowedSkewInSeconds: nested.allowedSkewInSeconds ?? options.allowedSkewInSeconds }
  const { clientAttestation, dpop } = await verifyAuthorizationRequest({
    ...options,
    dpop: withSkew(options.dpop),
    clientAttestation: withSkew(options.clientAttestation),
  })

  return {
    dpop,
    clientAttestation,
    jar,
  }
}
