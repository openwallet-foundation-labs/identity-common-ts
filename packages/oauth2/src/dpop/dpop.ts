import { type FetchHeaders, URL } from '@openid4vc/utils'
import { base64url, dateToSeconds, IdentityError, type OrPromise, parseWithErrorHandling } from '@owf/identity-common'
import {
  calculateJwkThumbprint,
  type DecodeJwtResult,
  decodeJwt,
  JoseInvalidArgumentError,
  type JwsSignerJwk,
  signJwt,
  verifyJwt,
  zCompactJwt,
} from '@owf/jose'
import type { CallbackContext } from '../callbacks'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { Oauth2Error } from '../error/Oauth2Error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import { type DpopJwtHeader, type DpopJwtPayload, zDpopJwtHeader, zDpopJwtPayload } from './z-dpop'

export interface RequestDpopOptions {
  /**
   * Dpop nonce to use for constructing the dpop jwt
   */
  nonce?: string

  /**
   * The signer of the dpop jwt
   */
  signer: JwsSignerJwk
}

export async function createDpopHeadersForRequest(options: CreateDpopJwtOptions) {
  const dpopJwt = await createDpopJwt(options)

  return {
    DPoP: dpopJwt,
  }
}

export interface CreateDpopJwtOptions {
  request: Omit<RequestLike, 'headers'>

  /**
   * Dpop nonce value
   */
  nonce?: string

  /**
   * Creation time of the JWT. If not provided the current date will be used
   */
  issuedAt?: Date

  /**
   * Additional payload to include in the dpop jwt payload. Will be applied after
   * any default claims that are included, so add claims with caution.
   */
  additionalPayload?: Record<string, unknown>

  /**
   * The access token to which the dpop jwt should be bound. Required
   * when the dpop will be sent along with an access token.
   *
   * If provided, the `hashCallback` parameter also needs to be provided
   */
  accessToken?: string

  /**
   * Callback used for dpop
   */
  callbacks: Pick<CallbackContext, 'generateRandom' | 'hash' | 'signJws'>

  /**
   * The signer of the dpop jwt. Only jwk signer allowed.
   */
  signer: JwsSignerJwk
}

export async function createDpopJwt(options: CreateDpopJwtOptions) {
  // Calculate access token hash
  let ath: string | undefined
  if (options.accessToken) {
    ath = base64url.encode(await options.callbacks.hash(options.accessToken, 'sha-256'))
  }

  const header = parseWithErrorHandling(zDpopJwtHeader, {
    typ: 'dpop+jwt',
    jwk: options.signer.publicJwk,
    alg: options.signer.alg,
  } satisfies DpopJwtHeader)

  const payload = parseWithErrorHandling(zDpopJwtPayload, {
    htu: htuFromRequestUrl(options.request.url),
    iat: dateToSeconds(options.issuedAt ?? new Date()),
    htm: options.request.method,
    jti: base64url.encode(await options.callbacks.generateRandom(32)),
    ath,
    nonce: options.nonce,
    ...options.additionalPayload,
  } satisfies DpopJwtPayload)

  const { jwt } = await signJwt({ header, payload, signer: options.signer, signJwsCallback: options.callbacks.signJws })

  return jwt
}

export interface DpopVerificationOptions {
  /**
   * Allowed dpop signing alg values. If not provided
   * any alg values are allowed and it's up to the `verifyJwsCallback`
   * to handle the alg.
   */
  allowedSigningAlgs?: string[]

  /**
   * Maximum accepted age in seconds for the DPoP proof based on the `iat` claim. The proof is rejected
   * when it is older than this value, as a server must accept a proof only for a limited time (RFC 9449
   * Section 11.1).
   *
   * @default 300
   */
  maxProofAgeSeconds?: number

  /**
   * Expected nonce in the payload, as provided by the server (RFC 9449 Section 8). If not provided the
   * nonce won't be validated.
   */
  expectedNonce?: string

  /**
   * Allowed clock skew in seconds for the `exp`, `nbf` and `iat` checks of the proof, including the
   * `maxProofAgeSeconds` check.
   *
   * @default 30
   */
  allowedSkewInSeconds?: number

  /**
   * Callback to enforce one-time usage of the DPoP proof `jti`.
   *
   * Return `true` to accept the proof as not replayed, `false` to reject as replayed.
   */
  assertJtiUniqueness?: DpopAssertJtiUniquenessCallback
}

export interface VerifyDpopJwtOptions extends DpopVerificationOptions {
  /**
   * The compact dpop jwt.
   */
  dpopJwt: string

  /**
   * The request for which to verify the dpop jwt
   */
  request: RequestLike

  /**
   * Access token to which the dpop jwt is bound. If provided the sha-256 hash of the
   * access token needs to match the 'ath' claim.
   */
  accessToken?: string

  /**
   * The expected jwk thumprint 'jti' confirmation method. If provided the thumprint of the
   * jwk used to sign the dpop jwt must match this provided thumbprint value. The 'jti' value
   * can be extracted from the access token payload, or if opaque tokens are used can be retrieved
   * using token introspection.
   */
  expectedJwkThumbprint?: string

  /**
   * Callbacks used for verifying dpop jwt
   */
  callbacks: Pick<CallbackContext, 'verifyJws' | 'hash'>

  now?: Date
}

export interface DpopAssertJtiUniquenessOptions extends DecodeJwtResult<typeof zDpopJwtHeader, typeof zDpopJwtPayload> {
  jwkThumbprint: string
  now: Date
}

export type DpopAssertJtiUniquenessCallback = (options: DpopAssertJtiUniquenessOptions) => OrPromise<boolean>

// RFC 9449 Section 11.1: a proof is only accepted for a limited time, or a leaked proof could be replayed forever
const DEFAULT_MAX_PROOF_AGE_SECONDS = 300

export async function verifyDpopJwt(options: VerifyDpopJwtOptions) {
  try {
    const decodedDpopJwt = decodeJwt({
      jwt: options.dpopJwt,
      headerSchema: zDpopJwtHeader,
      payloadSchema: zDpopJwtPayload,
    })
    const { header, payload } = decodedDpopJwt

    if (options.allowedSigningAlgs && !options.allowedSigningAlgs.includes(header.alg)) {
      throw new Oauth2Error(
        `dpop jwt uses alg value '${header.alg}' but allowed dpop signging alg values are ${options.allowedSigningAlgs.join(', ')}.`
      )
    }

    if (options.request.method !== payload.htm) {
      throw new Oauth2Error(
        `Dpop jwt contains htm value '${payload.htm}', but expected htm value '${options.request.method}'`
      )
    }

    // RFC 9449 §4.3: query and fragment are ignored, and both sides are normalized (RFC 3986 §6.2.2, §6.2.3)
    const expectedHtu = htuFromRequestUrl(options.request.url)
    if (expectedHtu !== htuFromRequestUrl(payload.htu)) {
      throw new Oauth2Error(`Dpop jwt contains htu value '${payload.htu}', but expected htu value '${expectedHtu}'.`)
    }

    if (options.accessToken) {
      const expectedAth = base64url.encode(await options.callbacks.hash(options.accessToken, 'sha-256'))

      if (!payload.ath) {
        throw new Oauth2Error(`Dpop jwt does not have a ath value, but expected ath value '${expectedAth}'.`)
      }

      if (payload.ath !== expectedAth) {
        throw new Oauth2Error(`Dpop jwt contains ath value '${payload.ath}', but expected ath value '${expectedAth}'.`)
      }
    }

    const jwkThumbprint = await calculateJwkThumbprint({
      hashAlgorithm: 'sha-256',
      hashCallback: options.callbacks.hash,
      jwk: header.jwk,
    })

    if (options.expectedJwkThumbprint && options.expectedJwkThumbprint !== jwkThumbprint) {
      throw new Oauth2Error(
        `Dpop is signed with jwk with thumbprint value '${jwkThumbprint}', but expect jwk thumbprint value '${options.expectedJwkThumbprint}'`
      )
    }

    await verifyJwt({
      signer: {
        alg: header.alg,
        method: 'jwk',
        publicJwk: header.jwk,
      },
      now: options.now,
      jwt: decodedDpopJwt,
      verifyJwsCallback: options.callbacks.verifyJws,
      errorMessage: 'dpop jwt verification failed',
      expectedNonce: options.expectedNonce,
      maxAgeSeconds: options.maxProofAgeSeconds ?? DEFAULT_MAX_PROOF_AGE_SECONDS,
      skewSeconds: options.allowedSkewInSeconds,
    })

    // The replay check comes after the signature check, so a proof that does not verify can't use up a `jti`
    if (options.assertJtiUniqueness) {
      const isUnique = await options.assertJtiUniqueness({
        ...decodedDpopJwt,
        jwkThumbprint,
        now: options.now ?? new Date(),
      })

      if (!isUnique) {
        throw new Oauth2Error(`Dpop jwt with jti value '${payload.jti}' has already been used.`)
      }
    }

    return {
      header,
      payload,
      jwkThumbprint,
    }
  } catch (error) {
    // A wrong option, such as a negative skew, is a mistake of the server, not of the proof
    if (error instanceof IdentityError && !(error instanceof JoseInvalidArgumentError)) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidDpopProof,
          error_description: error.message,
        },
        { cause: error }
      )
    }

    throw error
  }
}

function htuFromRequestUrl(requestUrl: string) {
  const htu = new URL(requestUrl)
  htu.search = ''
  htu.hash = ''

  return htu.toString()
}

export function extractDpopNonceFromHeaders(headers: FetchHeaders) {
  return headers.get('DPoP-Nonce')
}

export function extractDpopJwtFromHeaders(headers: FetchHeaders): { valid: true; dpopJwt?: string } | { valid: false } {
  const dpopJwt = headers.get('DPoP')

  if (!dpopJwt) {
    return { valid: true }
  }

  if (!zCompactJwt.safeParse(dpopJwt).success) {
    return { valid: false }
  }

  return { valid: true, dpopJwt }
}
