/** JAdES signing (ETSI TS 119 182-1 V1.2.1), on the JWS signing of `@owf/jose`. */

import {
  hasValidationErrors,
  parseWithSchema,
  prefixIssuePaths,
  type SchemaValidationCode,
  ValidationIssues,
} from '@owf/identity-common'
import {
  type FlattenedJws,
  type GeneralJws,
  type Jwk,
  type JwsPayload,
  type JwsSigner,
  jwsHeaderFromSigner,
  type SignJwsCallback,
  signCompactJws,
  signFlattenedJws,
  signGeneralJws,
} from '@owf/jose'
import { CRITICAL_PARAMETERS, DETACHED_MECHANISM_IDS } from './constants'
import { JadesValidationError } from './jades-error'
import { zProtectedHeaderForSigning, zUnprotectedHeader } from './schemas'
import type { ProtectedHeader, ProtectedHeaderParams, SigD, UnprotectedHeaderParams } from './types'
import { getSigningTime } from './utils'
import { JADES_VALIDATION_CODES, type JadesValidationCode } from './validation'

/** The JWS serializations a JAdES signature can be in (clause 5.1) */
export interface JadesSerializations {
  compact: string
  flattened: FlattenedJws
  general: GeneralJws
}

export type JadesSerialization = keyof JadesSerializations

export interface SignJadesOptions<Serialization extends JadesSerialization = 'compact'> {
  /**
   * The serialization to produce. Only `flattened` and `general` can carry an unprotected header.
   *
   * @default 'compact'
   */
  serialization?: Serialization

  /**
   * Protected header parameters besides `alg` and the parameters that identify the key, which are taken from `signer`.
   * A signature needs a reference to the signing certificate (clause 5.1.7 and 5.1.8): an `x5c` signer gives it, or
   * set `x5t#S256`, `x5t#o` or `sigX5ts`.
   */
  protectedHeader?: ProtectedHeaderParams

  /** The unprotected header, with the `etsiU` unsigned properties (clause 5.3) */
  unprotectedHeader?: UnprotectedHeaderParams

  /**
   * The JWS Payload. An object is serialized as JSON. With `sigD` it is the constructed detached payload, and absent for
   * `ObjectIdByURIHash`, which signs an empty payload (clause 5.2.8).
   */
  payload?: JwsPayload

  /** Signs a detached payload (clause 5.2.8). `HttpHeaders` sets `b64` to false. */
  sigD?: SigD

  /**
   * The claimed signing time (`iat`, clause 5.2.1), as Unix seconds or a date.
   *
   * @default now
   */
  signingTime?: number | Date

  /** The signer, which the callback resolves into a key */
  signer: JwsSigner

  /** Callback that produces the signature, see `@owf/jose` */
  signJwsCallback: SignJwsCallback
}

export interface SignJadesResult<Serialization extends JadesSerialization = 'compact'> {
  /** The signature in the requested serialization. Without the payload when it is detached. */
  jws: JadesSerializations[Serialization]
  /** The protected header that was signed */
  protectedHeader: ProtectedHeader
  /** The public key the JWS was signed with, as reported by the callback */
  signerJwk: Jwk
}

/**
 * Create a JAdES signature: the protected header with the claimed signing time is validated against clause 5 before it is
 * signed, and `sigD` and `b64` are marked critical.
 *
 * @throws JadesValidationError with an issue for each way the headers or the payload do not meet ETSI TS 119 182-1.
 *   Issue paths start with `protected`, `header` or `payload`, as in a JSON serialization.
 * @throws The errors of `signCompactJws`, `signFlattenedJws` and `signGeneralJws` of `@owf/jose`
 */
export async function signJades<Serialization extends JadesSerialization = 'compact'>(
  options: SignJadesOptions<Serialization>
): Promise<SignJadesResult<Serialization>> {
  const { signingTime = getSigningTime(), signer, signJwsCallback } = options
  // Clause 5.2.8.1: a JWS Payload signed with sigD is detached, wherever sigD is given
  const sigD = options.sigD ?? options.protectedHeader?.sigD
  const serialization = options.serialization ?? 'compact'

  const header: ProtectedHeaderParams = {
    ...options.protectedHeader,
    ...jwsHeaderFromSigner(signer),
    iat: signingTime instanceof Date ? Math.floor(signingTime.getTime() / 1000) : signingTime,
    ...(sigD && { sigD }),
    ...(sigD?.mId === DETACHED_MECHANISM_IDS.httpHeaders && { b64: false }),
  }
  const crit = new Set([...(header.crit ?? []), ...CRITICAL_PARAMETERS.filter((parameter) => parameter in header)])
  if (crit.size) header.crit = [...crit]

  const issues = new ValidationIssues<JadesValidationCode | SchemaValidationCode>()
  const result = parseWithSchema(zProtectedHeaderForSigning, header, { codes: JADES_VALIDATION_CODES })
  if (!result.success) issues.issues.push(...prefixIssuePaths('protected', result.issues))

  if (options.unprotectedHeader) {
    if (serialization === 'compact') {
      issues.add({
        code: 'not_allowed',
        path: ['header'],
        message: 'Compact JWS cannot carry the etsiU unprotected header',
      })
    }
    const unprotected = parseWithSchema(zUnprotectedHeader, options.unprotectedHeader, {
      codes: JADES_VALIDATION_CODES,
    })
    if (!unprotected.success) issues.issues.push(...prefixIssuePaths('header', unprotected.issues))
  }

  // Clause 5.2.8.3: ObjectIdByURIHash signs an empty JWS Payload, as `hashV` holds the digests of the objects
  const objectByUriHash = sigD?.mId === DETACHED_MECHANISM_IDS.objectByUriHash
  if (objectByUriHash && options.payload !== undefined) {
    issues.add({
      code: 'not_allowed',
      path: ['payload'],
      message: 'ObjectIdByURIHash signs an empty JWS Payload, so no payload can be given',
    })
  }
  if (!objectByUriHash && options.payload === undefined) {
    issues.add({
      code: 'missing_value',
      path: ['payload'],
      message: sigD ? 'The constructed detached JWS Payload is required' : 'The JWS Payload is required',
      context: { expected: 'payload' },
    })
  }

  if (!result.success || hasValidationErrors(issues.issues)) {
    throw new JadesValidationError('Invalid JAdES signature', issues.issues)
  }
  const protectedHeader = result.data as ProtectedHeader

  const signOptions = {
    protectedHeader,
    unprotectedHeader: options.unprotectedHeader,
    payload: options.payload ?? new Uint8Array(),
    detachPayload: sigD !== undefined,
    signer,
    signJwsCallback,
  }

  const signed =
    serialization === 'compact'
      ? await signCompactJws(signOptions).then(({ compact, signerJwk }) => ({ jws: compact, signerJwk }))
      : serialization === 'flattened'
        ? await signFlattenedJws(signOptions)
        : await signGeneralJws({ ...signOptions, signatures: [signOptions] }).then(({ jws, signatures }) => ({
            jws,
            signerJwk: signatures[0].signerJwk,
          }))

  return { jws: signed.jws as JadesSerializations[Serialization], protectedHeader, signerJwk: signed.signerJwk }
}
