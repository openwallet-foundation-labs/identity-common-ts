/** JAdES decoding and verification (ETSI TS 119 182-1 V1.2.1), on the JWS verification of `@owf/jose`. */
import { parseWithErrorHandling, type SchemaValidationCode, ValidationIssues } from '@owf/identity-common'
import {
  type DecodeJwtResult,
  decodeBase64UrlJsonObject,
  type FlattenedJws,
  type GeneralJws,
  JoseNotSupportedError,
  JoseValidationError,
  type JwsSignerWithJwk,
  type ParsedJws,
  parseJws,
  type VerifyJwsCallback,
  type VerifyJwsSignatureOptions,
  type VerifyJwtClaimsOptions,
  type VerifyJwtResult,
  verifyJwsSignature,
  verifyJwt,
  zJwtPayload,
} from '@owf/jose'
import { CRITICAL_PARAMETERS, DETACHED_MECHANISM_IDS, JadesProfile } from './constants'
import { JadesValidationError } from './jades-error'
import { type ProfileValidationOptions, validateProfile } from './profile'
import type { zProtectedHeader, zUnprotectedHeader } from './schemas'
import type { ProtectedHeader, UnprotectedHeaderParams } from './types'
import type { JadesValidationCode } from './validation'

export interface DecodeJadesOptions {
  /** The signature: a compact serialization, or a flattened or general JSON serialization */
  jws: string | FlattenedJws | GeneralJws

  /** The detached JWS Payload (clause 5.2.8). Not needed for `ObjectIdByURIHash`, which signs an empty payload. */
  detachedPayload?: string | Uint8Array

  /**
   * Which signature of a general JSON serialization to read
   *
   * @default 0
   */
  signatureIndex?: number

  /**
   * The baseline profile the signature has to meet (clause 6.3)
   *
   * @default JadesProfile.B_B
   */
  profile?: JadesProfile

  /** Evidence of validation data `validateProfile` cannot inspect, for B-LT and B-LTA */
  profileOptions?: ProfileValidationOptions

  /** Critical header parameters the caller understands, besides `sigD` and `b64` */
  understoodCriticalParameters?: ReadonlyArray<string>
}

/** A decoded JAdES signature, with the JAdES protected and unprotected header */
export type DecodedJades = ParsedJws<typeof zProtectedHeader, typeof zUnprotectedHeader>

export interface VerifyJadesOptions
  extends DecodeJadesOptions,
    Pick<VerifyJwsSignatureOptions, 'allowedAlgorithms' | 'allowedSignerMethods'> {
  /** Verifies the signature and decides whether the signing certificate is trusted, see `@owf/jose` */
  verifyJwsCallback: VerifyJwsCallback
}

export interface VerifyJadesResult extends DecodedJades {
  /** The signer, with the public key the signature was verified with */
  signer: JwsSignerWithJwk
}

export interface DecodeJadesJwtOptions
  extends Omit<DecodeJadesOptions, 'jws' | 'detachedPayload' | 'signatureIndex' | 'understoodCriticalParameters'> {
  /** A JWT signed as a compact JAdES signature */
  jwt: string

  /** Critical header parameters the caller understands. A JWT uses neither `sigD` nor `b64`, so none by default. */
  understoodCriticalParameters?: ReadonlyArray<string>
}

/** A decoded JWT signed as a compact JAdES signature, as `decodeJwt` of `@owf/jose` returns it */
export type DecodedJadesJwt = DecodeJwtResult<typeof zProtectedHeader>

export interface VerifyJadesJwtOptions
  extends Omit<VerifyJadesOptions, 'jws' | 'detachedPayload' | 'signatureIndex' | 'understoodCriticalParameters'>,
    Pick<DecodeJadesJwtOptions, 'understoodCriticalParameters'>,
    VerifyJwtClaimsOptions {
  /**
   * A JWT signed as a compact JAdES signature, or what {@link decodeJadesJwt} returned for it. `profile`,
   * `profileOptions` and `understoodCriticalParameters` were applied when that was decoded, and are not used again.
   * It is verified as it is passed, like `verifyJwt` of `@owf/jose` does, so pass it unmodified.
   */
  jwt: string | DecodedJadesJwt
}

/**
 * Decode a JAdES signature without verifying it: the JWS as `@owf/jose` parses it, the protected and unprotected header
 * against clause 5, and the baseline profile.
 *
 * @throws JadesValidationError with an issue for each way the headers do not meet clause 5 or the baseline profile. Issue
 *   paths start with `protected` or `header`, as in a JSON serialization.
 * @throws The errors of `parseJws` of `@owf/jose`, e.g. a `JoseValidationError` for a header that does not meet clause 5
 */
export function decodeJades(options: DecodeJadesOptions): DecodedJades {
  return decode(options, false)
}

/**
 * {@link decodeJades}, and for `isJwt` a signature that is a JWT. A JWT attaches its claims set as the base64url JWS
 * Payload, so it uses neither `sigD` nor `b64`, and they are not understood in `crit` unless the caller names them.
 */
function decode(options: DecodeJadesOptions, isJwt: boolean): DecodedJades {
  const signatureIndex = options.signatureIndex ?? 0
  // Not for a JWT, so `parseJws` rejects its empty payload
  const objectByUriHash = !isJwt && isObjectByUriHash(options.jws, signatureIndex)
  const decoded = parseJws({
    jws: options.jws,
    detachedPayload: objectByUriHash ? '' : options.detachedPayload,
    signatureIndex,
    understoodCriticalParameters: [
      ...(isJwt ? [] : CRITICAL_PARAMETERS),
      ...(options.understoodCriticalParameters ?? []),
    ],
  })

  // Reached when the caller understands `b64`. The error is that of `decodeJwt` of `@owf/jose`.
  if (isJwt && decoded.registeredProtectedHeader.b64 === false) {
    throw new JoseNotSupportedError(
      `Unable to decode the JWT, its header sets 'b64' to false. An unencoded payload is not valid for a JWT.`
    )
  }

  // The JAdES checks are made here rather than as schemas of `parseJws`, so their issues keep the JAdES codes
  const profile = options.profile ?? JadesProfile.B_B
  const protectedHeader = decoded.protectedHeader as ProtectedHeader
  const unprotectedHeader = decoded.unprotectedHeader as UnprotectedHeaderParams | undefined

  // The payload is attached here, as without a detached payload `parseJws` rejects a JWS that has none
  if (protectedHeader.sigD && !objectByUriHash && options.detachedPayload === undefined) {
    const issues = new ValidationIssues<JadesValidationCode | SchemaValidationCode>()
    issues.add({
      code: 'not_allowed',
      path: ['payload'],
      message: 'sigD is not allowed in a signature whose JWS Payload is attached (clause 5.2.8.1)',
    })
    throw new JadesValidationError('Invalid JAdES signature', issues.issues)
  }

  const result = validateProfile(protectedHeader, profile, unprotectedHeader, options.profileOptions)
  if (!result.valid) {
    throw new JadesValidationError(`The signature does not meet the JAdES ${profile} profile`, result.issues)
  }

  return { ...decoded, protectedHeader, unprotectedHeader }
}

/**
 * Verify a JAdES signature: {@link decodeJades}, and then the signature through `verifyJwsCallback`. For
 * `ObjectIdByURIHash` the signature covers the `hashV` digests only, so the caller checks each object of `pars` against
 * them.
 *
 * @throws The errors of {@link decodeJades}, and of `verifyJwsSignature` of `@owf/jose`
 */
export async function verifyJades(options: VerifyJadesOptions): Promise<VerifyJadesResult> {
  const decoded = decodeJades(options)
  const { signer } = await verifyJwsSignature({
    // The checks use the registered header, which `decoded` carries
    jws: { ...decoded, protectedHeader: decoded.registeredProtectedHeader },
    verifyJwsCallback: options.verifyJwsCallback,
    allowedAlgorithms: options.allowedAlgorithms,
    allowedSignerMethods: options.allowedSignerMethods,
  })

  return { ...decoded, signer }
}

/**
 * Decode a JWT signed as a JAdES signature without verifying it: {@link decodeJades}, and the claims set as `decodeJwt`
 * of `@owf/jose` validates it. Pass the result to {@link verifyJadesJwt} to verify it without decoding it again.
 *
 * @throws The errors of {@link decodeJades}, and of `decodeJwt` of `@owf/jose`. A signature that is not a JWT is
 *   rejected: one with `sigD`, without a payload, or with `b64` false.
 */
export function decodeJadesJwt({
  jwt,
  profile,
  profileOptions,
  understoodCriticalParameters,
}: DecodeJadesJwtOptions): DecodedJadesJwt {
  const jades = decode({ jws: jwt, profile, profileOptions, understoodCriticalParameters }, true)

  // The header was parsed and validated by `decode`, so only the claims set is left
  const payload = parseWithErrorHandling(
    zJwtPayload,
    decodeBase64UrlJsonObject(jades.encodedPayload, 'JWT payload'),
    'Invalid JWT payload',
    JoseValidationError
  )
  return {
    header: jades.protectedHeader as DecodedJadesJwt['header'],
    payload,
    registeredHeader: jades.registeredProtectedHeader,
    registeredPayload: payload,
    payloadBytes: jades.payload,
    signature: jades.signature,
    signingInput: jades.signingInput,
    compact: jwt,
  }
}

/**
 * Verify a JWT signed as a JAdES signature: {@link decodeJadesJwt}, and then `verifyJwt` of `@owf/jose`, which verifies
 * the signature and the claims, such as `exp` and `iat` against `now`.
 *
 * @throws The errors of {@link decodeJadesJwt}, and of `verifyJwt` of `@owf/jose`
 */
export async function verifyJadesJwt({
  jwt,
  profile,
  profileOptions,
  understoodCriticalParameters,
  ...options
}: VerifyJadesJwtOptions): Promise<VerifyJwtResult<typeof zProtectedHeader>> {
  const decoded =
    typeof jwt === 'string' ? decodeJadesJwt({ jwt, profile, profileOptions, understoodCriticalParameters }) : jwt

  return verifyJwt<typeof zProtectedHeader>({ ...options, jwt: decoded })
}

/** Whether the signature uses `ObjectIdByURIHash`, whose empty JWS Payload the caller is not given (clause 5.2.8.3) */
function isObjectByUriHash(jws: DecodeJadesOptions['jws'], signatureIndex: number): boolean {
  try {
    const encoded =
      typeof jws === 'string'
        ? jws.split('.')[0]
        : 'signatures' in jws
          ? (jws as GeneralJws).signatures[signatureIndex]?.protected
          : (jws as FlattenedJws).protected
    const { sigD } = decodeBase64UrlJsonObject(encoded ?? '', 'JWS protected header') as { sigD?: { mId?: unknown } }
    return sigD?.mId === DETACHED_MECHANISM_IDS.objectByUriHash
  } catch {
    // Left for `parseJws` to reject
    return false
  }
}
