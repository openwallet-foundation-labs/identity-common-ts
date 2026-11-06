import { base64url, parseWithErrorHandling, stringToBytes, zBase64Url } from '@owf/identity-common'
import type { SignJwsCallback } from '../callbacks'
import { JoseInvalidArgumentError, JoseValidationError } from '../error'
import type { Jwk } from '../jwk/z-jwk'
import { decodeUnencodedPayload, encodeBase64UrlJson, unencodedCompactPayloadIssue } from '../utils/encoding'
import { hasOwn } from '../utils/object'
import { assertCriticalHeaderParameters, isPayloadBase64UrlEncoded } from './critical-headers'
import type { JwsSigner } from './signer'
import {
  type FlattenedJws,
  type GeneralJws,
  type JwsUnprotectedHeader,
  zJwsProtectedHeader,
  zJwsUnprotectedHeader,
} from './z-jws'

/** The payload of a JWS. An object is serialized as JSON, a string is encoded as UTF-8. */
export type JwsPayload = Record<string, unknown> | string | Uint8Array

export interface SignCompactJwsOptions {
  /** The protected header, validated against {@link zJwsProtectedHeader}. Its `alg` must be the signer's. */
  protectedHeader: Record<string, unknown>

  /** The payload. An object is serialized as JSON, a string is encoded as UTF-8. */
  payload: JwsPayload

  /** The signer, which the callback resolves into a key. */
  signer: JwsSigner

  /** Callback that produces the signature. */
  signJwsCallback: SignJwsCallback

  /**
   * Whether to leave the payload out of the serialization, to carry it out of band.
   *
   * @default false
   */
  detachPayload?: boolean
}

export interface SignCompactJwsResult {
  /** The compact serialization. Its payload part is empty when `detachPayload` was set. */
  compact: string

  /** The signature, base64url encoded. */
  signature: string

  /** The bytes that were signed, as a string. */
  signingInput: string

  /** The public key the JWS was signed with, as reported by the callback. */
  signerJwk: Jwk
}

export interface SignFlattenedJwsOptions extends SignCompactJwsOptions {
  /** The unprotected header, which is not covered by the signature. Its parameters must not be in the protected header. */
  unprotectedHeader?: JwsUnprotectedHeader
}

export interface SignFlattenedJwsResult extends Omit<SignCompactJwsResult, 'compact'> {
  /** The flattened JSON serialization. Without `payload` when `detachPayload` was set. */
  jws: FlattenedJws
}

export interface SignGeneralJwsOptions
  extends Pick<SignCompactJwsOptions, 'payload' | 'signJwsCallback' | 'detachPayload'> {
  /** The signatures over the payload, each with its own headers and signer. All must agree on `b64`. */
  signatures: [GeneralJwsSignatureOptions, ...GeneralJwsSignatureOptions[]]
}

export type GeneralJwsSignatureOptions = Pick<
  SignFlattenedJwsOptions,
  'protectedHeader' | 'unprotectedHeader' | 'signer'
>

export interface SignGeneralJwsResult {
  /** The general JSON serialization. Without `payload` when `detachPayload` was set. */
  jws: GeneralJws

  /** The result of each signature, in the order of `signatures`. */
  signatures: Array<Omit<SignCompactJwsResult, 'compact'>>
}

/**
 * Signs a JWS in compact serialization. The callback signs the exact bytes that end up in the token.
 *
 * @throws JoseValidationError if the protected header is not a valid JWS header.
 * @throws JoseValidationError with an `invalid_crit` issue if `crit` is invalid.
 * @throws JoseNotSupportedError if the payload is unencoded (`b64` is false) and not valid UTF-8.
 * @throws JoseInvalidArgumentError if the signer uses another algorithm than the header names, the
 *   callback does not return a base64url encoded signature, or the payload is unencoded, not detached,
 *   and contains a character RFC 7797 does not allow in a compact serialization: a '.', or anything
 *   outside printable ASCII.
 */
export async function signCompactJws(options: SignCompactJwsOptions): Promise<SignCompactJwsResult> {
  const { encodedProtectedHeader, encodedPayload, ...result } = await signJwsPart({
    ...options,
    serialization: 'compact',
  })

  return {
    compact: `${encodedProtectedHeader}.${options.detachPayload ? '' : encodedPayload}.${result.signature}`,
    ...result,
  }
}

/**
 * Signs a JWS in flattened JSON serialization, which can carry an unprotected header.
 *
 * @throws See {@link signCompactJws}, except that an unencoded payload is not limited to printable ASCII.
 * @throws JoseValidationError if the unprotected header is not an object, or has `crit`.
 * @throws JoseInvalidArgumentError if a parameter is in both the protected and the unprotected header.
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2
 */
export async function signFlattenedJws(options: SignFlattenedJwsOptions): Promise<SignFlattenedJwsResult> {
  const { encodedProtectedHeader, encodedPayload, unprotectedHeader, ...result } = await signJwsPart({
    ...options,
    serialization: 'json',
  })

  return {
    jws: {
      ...(options.detachPayload ? {} : { payload: encodedPayload }),
      protected: encodedProtectedHeader,
      ...(unprotectedHeader ? { header: unprotectedHeader } : {}),
      signature: result.signature,
    },
    ...result,
  }
}

/**
 * Signs a JWS in general JSON serialization: one payload with one or more signatures.
 *
 * @throws See {@link signFlattenedJws}.
 * @throws JoseInvalidArgumentError if the signatures do not agree on `b64`, as they share the payload.
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
 */
export async function signGeneralJws(options: SignGeneralJwsOptions): Promise<SignGeneralJwsResult> {
  const parts = []
  for (const signature of options.signatures) {
    parts.push(
      await signJwsPart({
        ...signature,
        payload: options.payload,
        signJwsCallback: options.signJwsCallback,
        serialization: 'json',
      })
    )
  }

  // RFC 7797 section 7: the payload is encoded once, so every signature has to encode it the same way
  const [{ encodedPayload }] = parts
  if (parts.some((part) => part.encodedPayload !== encodedPayload)) {
    throw new JoseInvalidArgumentError(
      'Unable to sign the JWS, the signatures of a general JSON serialization must all use the same b64 value.'
    )
  }

  return {
    jws: {
      ...(options.detachPayload ? {} : { payload: encodedPayload }),
      signatures: parts.map(({ encodedProtectedHeader, unprotectedHeader, signature }) => ({
        protected: encodedProtectedHeader,
        ...(unprotectedHeader ? { header: unprotectedHeader } : {}),
        signature,
      })),
    },
    signatures: parts.map(({ signature, signingInput, signerJwk }) => ({ signature, signingInput, signerJwk })),
  }
}

/** Validates the headers and signs the payload with them, for any serialization. */
async function signJwsPart(
  options: Omit<SignFlattenedJwsOptions, 'detachPayload'> & {
    serialization: 'compact' | 'json'
    detachPayload?: boolean
  }
) {
  const protectedHeader = parseWithErrorHandling(
    zJwsProtectedHeader,
    options.protectedHeader,
    'Unable to sign the JWS, invalid header',
    JoseValidationError
  )
  const unprotectedHeader = options.unprotectedHeader
    ? parseWithErrorHandling(
        zJwsUnprotectedHeader,
        options.unprotectedHeader,
        'Unable to sign the JWS, invalid unprotected header',
        JoseValidationError
      )
    : undefined

  // RFC 7515 section 7.2.1: the protected and the unprotected header are disjoint
  const duplicates = Object.keys(unprotectedHeader ?? {}).filter((name) => hasOwn(protectedHeader, name))
  if (duplicates.length > 0) {
    throw new JoseInvalidArgumentError(
      `Unable to sign the JWS, the header parameter(s) ${duplicates.map((name) => `'${name}'`).join(', ')} are in both the protected and the unprotected header.`
    )
  }

  // A producer understands what it marks critical
  assertCriticalHeaderParameters({
    protectedHeader,
    unprotectedHeader,
    understoodCriticalParameters: protectedHeader.crit ?? [],
  })

  if (options.signer.alg !== protectedHeader.alg) {
    throw new JoseInvalidArgumentError(
      `Unable to sign the JWS, the header says alg '${protectedHeader.alg}' but the signer signs with alg '${options.signer.alg}'.`
    )
  }

  const payload =
    typeof options.payload === 'string'
      ? stringToBytes(options.payload)
      : options.payload instanceof Uint8Array
        ? options.payload
        : stringToBytes(JSON.stringify(options.payload))

  const isBase64UrlEncoded = isPayloadBase64UrlEncoded(protectedHeader)

  const encodedProtectedHeader = encodeBase64UrlJson(protectedHeader)
  const encodedPayload = isBase64UrlEncoded ? base64url.encode(payload) : decodeUnencodedPayload(payload)
  const signingInput = `${encodedProtectedHeader}.${encodedPayload}`

  // RFC 7797 section 5.2
  const compactPayloadIssue =
    options.serialization === 'compact' && !isBase64UrlEncoded && !options.detachPayload
      ? unencodedCompactPayloadIssue(encodedPayload)
      : undefined
  if (compactPayloadIssue) {
    throw new JoseInvalidArgumentError(
      `Unable to sign the JWS. ${compactPayloadIssue} Detach the payload, or leave out 'b64' so that it is base64url encoded.`
    )
  }

  const { signature, signerJwk } = await options.signJwsCallback(options.signer, {
    signingInput,
    signingInputBytes: stringToBytes(signingInput),
    protectedHeader,
    unprotectedHeader,
    payload,
    jwtPayload:
      typeof options.payload === 'object' && !(options.payload instanceof Uint8Array) ? options.payload : undefined,
  })

  // The signature is written into the token as it is, so it has to be what a parser accepts there
  if (!zBase64Url.min(1).safeParse(signature).success) {
    throw new JoseInvalidArgumentError(
      'Unable to sign the JWS, the signature returned by the signing callback is not a non-empty base64url string.'
    )
  }

  return { encodedProtectedHeader, encodedPayload, unprotectedHeader, signature, signingInput, signerJwk }
}
