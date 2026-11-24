import { parseWithSchema } from '@owf/identity-common'
import { decodeJwt, zCompactJwe } from '@owf/jose'
import z from 'zod'
import type { CallbackContext } from '../callbacks'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import { parseJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import { hasRequestUri, isJarAuthorizationRequest, zJarAuthorizationRequest } from '../jar/z-jar-authorization-request'
import { type ParseAuthorizationRequestResult, parseAuthorizationRequest } from './parse-authorization-request'
import {
  type AuthorizationRequest,
  pushedAuthorizationRequestUriPrefix,
  zAuthorizationRequest,
} from './z-authorization-request'

export interface ParsePushedAuthorizationRequestOptions {
  request: RequestLike
  authorizationRequest: unknown
  callbacks: Pick<CallbackContext, 'fetch' | 'fetchLimits'>
}
export interface ParsePushedAuthorizationRequestResult extends ParseAuthorizationRequestResult {
  authorizationRequest: AuthorizationRequest

  /**
   * The JWT-secured request object, if the request was pushed as a JAR.
   * May be undefined if the request object is not a JAR.
   */
  authorizationRequestJwt?: string
}

/**
 * Parse an pushed authorization request.
 *
 * @throws {Oauth2ServerErrorResponseError}
 */
export async function parsePushedAuthorizationRequest(
  options: ParsePushedAuthorizationRequestOptions
): Promise<ParsePushedAuthorizationRequestResult> {
  // RFC 9126 section 2.1: the request_uri parameter must not be provided in a pushed authorization request.
  // We check this before parsing the JAR, as otherwise the request_uri would be fetched.
  if (hasRequestUri(options.authorizationRequest)) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `The 'request_uri' parameter must not be provided in a pushed authorization request.`,
    })
  }

  const parsedRequest = parseWithSchema(
    z.union([zAuthorizationRequest, zJarAuthorizationRequest]),
    options.authorizationRequest
  )
  if (!parsedRequest.success) {
    throw Oauth2ServerErrorResponseError.fromValidationIssues(
      {
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Invalid authorization request. Could not parse authorization request or jar.',
      },
      parsedRequest.issues
    )
  }
  const parsed = parsedRequest.data

  let authorizationRequest: AuthorizationRequest
  let authorizationRequestJwt: string | undefined
  if (isJarAuthorizationRequest(parsed)) {
    const parsedJar = await parseJarRequest({
      jarRequestParams: parsed,
      callbacks: options.callbacks,
      allowRequestUri: false,
    })

    // RFC 9101 Section 7: invalid_request_object for an invalid request object
    const requestObjectIsEncrypted = zCompactJwe.safeParse(parsedJar.authorizationRequestJwt).success
    if (requestObjectIsEncrypted) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequestObject,
        error_description: 'Encrypted JWE request objects are not supported.',
      })
    }

    let jwt: ReturnType<typeof decodeJwt>
    try {
      jwt = decodeJwt({ jwt: parsedJar.authorizationRequestJwt })
    } catch (error) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidRequestObject,
          error_description: 'JAR request object is not a valid JWT.',
        },
        { cause: error }
      )
    }

    const parsedAuthorizationRequest = parseWithSchema(zAuthorizationRequest, jwt.payload)
    if (!parsedAuthorizationRequest.success) {
      throw Oauth2ServerErrorResponseError.fromValidationIssues(
        {
          error: Oauth2ErrorCodes.InvalidRequestObject,
          error_description: 'Invalid authorization request. Could not parse jar request payload.',
        },
        parsedAuthorizationRequest.issues
      )
    }

    authorizationRequest = parsedAuthorizationRequest.data
    authorizationRequestJwt = parsedJar.authorizationRequestJwt
  } else {
    authorizationRequest = parsed
  }

  const { clientAttestation, dpop } = parseAuthorizationRequest({
    authorizationRequest,
    request: options.request,
  })

  return {
    authorizationRequest,
    authorizationRequestJwt,
    dpop,
    clientAttestation,
  }
}

export interface ParsePushedAuthorizationRequestUriReferenceValueOptions {
  uri: string
}

/**
 * Parse a pushed authorization request URI prefixed with `urn:ietf:params:oauth:request_uri:`
 * and returns the identifier, without the prefix.
 *
 * @throws {Oauth2ServerErrorResponseError}
 */
export function parsePushedAuthorizationRequestUriReferenceValue(
  options: ParsePushedAuthorizationRequestUriReferenceValueOptions
): string {
  if (!options.uri.startsWith(pushedAuthorizationRequestUriPrefix)) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `The 'request_uri' must start with the prefix "${pushedAuthorizationRequestUriPrefix}".`,
    })
  }

  return options.uri.substring(pushedAuthorizationRequestUriPrefix.length)
}
