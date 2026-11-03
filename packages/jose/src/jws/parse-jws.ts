import { type BaseSchema, base64url, parseWithErrorHandling, stringToBytes, zBase64Url } from '@owf/identity-common'
import { JoseParseError, JoseValidationError } from '../error'
import {
  decodeBase64UrlBytes,
  decodeBase64UrlJsonObject,
  decodeUnencodedPayload,
  unencodedCompactPayloadIssue,
} from '../utils/encoding'
import { hasOwn } from '../utils/object'
import type { InferSchemaOrDefaultOutput } from '../utils/zod'
import { assertCriticalHeaderParameters, isPayloadBase64UrlEncoded } from './critical-headers'
import {
  type FlattenedJws,
  type GeneralJws,
  type JwsProtectedHeader,
  zFlattenedJws,
  zGeneralJws,
  zJwsProtectedHeader,
  zJwsUnprotectedHeader,
} from './z-jws'

export type JwsSerialization = 'compact' | 'flattened' | 'general'

export interface ParseJwsOptions<
  ProtectedHeaderSchema extends BaseSchema | undefined,
  UnprotectedHeaderSchema extends BaseSchema | undefined,
> {
  /**
   * The JWS to parse: a compact serialization, or a flattened or general JSON serialization.
   *
   * A string is always read as a compact serialization. A JSON serialized JWS has to be passed as a
   * value, so that what a token is never depends on what it happens to look like.
   */
  jws: string | FlattenedJws | GeneralJws

  /**
   * Schema for the protected header. The header is always validated against
   * {@link zJwsProtectedHeader} as well, so that `alg`, `crit` and `b64` are checked even when the
   * schema given here does not describe them.
   */
  protectedHeaderSchema?: ProtectedHeaderSchema

  /** Schema for the unprotected header of a JSON serialized JWS. */
  unprotectedHeaderSchema?: UnprotectedHeaderSchema

  /**
   * The payload, for a JWS that does not carry one. Required when the serialization has no payload,
   * and rejected when it does — a detached payload that disagrees with the carried one would mean
   * verifying different bytes than the ones that are returned.
   */
  detachedPayload?: string | Uint8Array

  /**
   * Which signature to read from a general JSON serialization.
   *
   * @default 0
   */
  signatureIndex?: number

  /** The critical header parameters the caller understands, see {@link assertCriticalHeaderParameters}. */
  understoodCriticalParameters?: ReadonlyArray<string>
}

export interface ParsedJws<
  ProtectedHeaderSchema extends BaseSchema | undefined = undefined,
  UnprotectedHeaderSchema extends BaseSchema | undefined = undefined,
> {
  serialization: JwsSerialization

  /** The validated protected header, as the schema that was given returned it. */
  protectedHeader: InferSchemaOrDefaultOutput<ProtectedHeaderSchema, typeof zJwsProtectedHeader>

  /**
   * The protected header as validated against {@link zJwsProtectedHeader} alone, whatever schema was
   * given.
   *
   * This is what the checks of this package are made on — the algorithm, the signer, `crit` and
   * `b64` — as a schema of the caller's can drop or change the parameters they depend on.
   */
  registeredProtectedHeader: JwsProtectedHeader

  /**
   * The validated unprotected header, when the serialization has one.
   *
   * Not covered by the signature, so nothing read from here is trustworthy.
   */
  unprotectedHeader?: InferSchemaOrDefaultOutput<UnprotectedHeaderSchema, typeof zJwsUnprotectedHeader>

  /** The protected header as it was received, base64url encoded. */
  encodedProtectedHeader: string

  /** The payload bytes. */
  payload: Uint8Array

  /**
   * The payload as it appears in the signing input: base64url encoded, or the payload itself when
   * `b64` is false.
   */
  encodedPayload: string

  /** The signature, base64url encoded. */
  signature: string

  /**
   * The exact bytes covered by the signature, as a string. ASCII, unless the payload is unencoded
   * (`b64` false) and detached or in a JSON serialization: the payload is then included without
   * encoding.
   *
   * Taken from the token as received rather than rebuilt from the parsed header, so that what is
   * verified is what was sent, down to the byte. Re-encoding a parsed header would produce different
   * bytes for the same header whenever member order or string escaping differs.
   *
   * @see https://www.rfc-editor.org/rfc/rfc7515#section-5.2
   */
  signingInput: string

  /**
   * The compact serialization, when that is what was parsed and it carries its payload. Not set for a
   * detached payload, as the compact serialization then does not contain what was signed.
   */
  compact?: string
}

/** The parts of a JWS, as they are laid out in the serialization it was received in. */
interface JwsParts {
  serialization: JwsSerialization
  encodedProtectedHeader: string | undefined
  unprotectedHeader: Record<string, unknown> | undefined
  /** `undefined` when the payload is detached. */
  serializedPayload: string | undefined
  signature: string
  compact?: string
}

/**
 * Whether the encoded protected header of a compact JWS sets `b64` to false, for reporting a JWS of
 * more than three parts: such a JWS carries its payload as it is, so a '.' in the payload is what
 * split it into more parts.
 */
const isUnencodedPayloadHeader = (encodedProtectedHeader: string): boolean => {
  try {
    return decodeBase64UrlJsonObject(encodedProtectedHeader, 'JWS protected header').b64 === false
  } catch {
    return false
  }
}

function compactJwsParts(jws: string): JwsParts {
  const parts = jws.split('.')
  if (parts.length > 3 && isUnencodedPayloadHeader(parts[0])) {
    // The header and the signature are base64url, so the payload is everything between them
    const issue = unencodedCompactPayloadIssue(parts.slice(1, -1).join('.'))
    throw new JoseParseError(`Unable to parse the JWS. ${issue}`)
  }
  if (parts.length !== 3) {
    throw new JoseParseError('Unable to parse the JWS, a compact JWS must consist of exactly three parts')
  }

  // The parts are checked here rather than only where they are decoded, so that a string that is not
  // a compact JWS is rejected as one, and so that the signature — which this package hands to a
  // callback without decoding it — cannot carry anything but base64url either.
  //
  // The payload is exempt: with `b64` set to false (RFC 7797) it is the payload itself rather than
  // base64url of it, and `resolvePayload` decodes it according to the header. An empty header is
  // reported by the caller, and an empty payload is how a detached payload is serialized, so its
  // emptiness is not rejected here.
  if (!zBase64Url.safeParse(parts[0]).success) {
    throw new JoseParseError('Unable to parse the JWS, the protected header of a compact JWS must be base64url')
  }
  if (!zBase64Url.safeParse(parts[2]).success) {
    throw new JoseParseError('Unable to parse the JWS, the signature of a compact JWS must be base64url')
  }

  // An empty signature is how an unsecured JWS is serialized. `alg: none` is never accepted, so there
  // is nothing a verification callback could check it against.
  if (parts[2] === '') {
    throw new JoseParseError(
      'Unable to parse the JWS, it does not have a signature. An unsecured JWS is not supported.'
    )
  }

  // An empty payload part means the payload is detached, and then the compact serialization does not
  // contain what was signed: verifying it as a whole would verify an empty payload instead.
  const isPayloadDetached = parts[1] === ''

  return {
    serialization: 'compact',
    encodedProtectedHeader: parts[0],
    unprotectedHeader: undefined,
    serializedPayload: isPayloadDetached ? undefined : parts[1],
    signature: parts[2],
    compact: isPayloadDetached ? undefined : jws,
  }
}

function jsonJwsParts(jws: FlattenedJws | GeneralJws, signatureIndex: number): JwsParts {
  // Checked before anything is read from it: a JSON serialized JWS is often what `JSON.parse` returned
  // for an untrusted body, which can be any JSON value.
  if (typeof jws !== 'object' || jws === null || Array.isArray(jws)) {
    throw new JoseParseError('Unable to parse the JWS, a JSON serialized JWS must be an object')
  }

  if ('signatures' in jws) {
    const general = parseWithErrorHandling(
      zGeneralJws,
      jws,
      'Unable to parse the general JSON serialized JWS',
      JoseValidationError
    )
    const signature = general.signatures[signatureIndex]

    if (!signature) {
      throw new JoseParseError(
        `Unable to parse the JWS, it does not contain a signature at index ${signatureIndex}. It contains ${general.signatures.length} signature(s).`
      )
    }

    return {
      serialization: 'general',
      encodedProtectedHeader: signature.protected,
      unprotectedHeader: signature.header,
      serializedPayload: general.payload,
      signature: signature.signature,
    }
  }

  const flattened = parseWithErrorHandling(
    zFlattenedJws,
    jws,
    'Unable to parse the flattened JSON serialized JWS',
    JoseValidationError
  )

  return {
    serialization: 'flattened',
    encodedProtectedHeader: flattened.protected,
    unprotectedHeader: flattened.header,
    serializedPayload: flattened.payload,
    signature: flattened.signature,
  }
}

/**
 * Parses and validates a JWS, without verifying the signature over it.
 *
 * The header is validated against {@link zJwsProtectedHeader} and, when given, the caller's own
 * schema. The signing input is taken from the token as received, so it can be handed to a
 * verification callback unchanged.
 *
 * What is deliberately not supported:
 *
 * - A JWS without a protected header. RFC 7515 allows one in the JSON serializations, but then `alg`
 *   is not integrity protected and the JWS says nothing about who signed it.
 * - Header parameters that appear in both the protected and the unprotected header, which RFC 7515
 *   forbids and which would make it ambiguous which of the two values applies.
 *
 * @throws JoseParseError if the JWS is not well-formed, which includes a compact JWS that carries an
 *   unencoded payload (`b64` is false) with a '.' or a character outside printable ASCII.
 * @throws JoseValidationError if a header does not validate against its schema.
 * @throws JoseValidationError with an `invalid_crit` or `unsupported_crit` issue if `crit` is invalid
 * or names a parameter that is not understood.
 * @throws JoseNotSupportedError if the payload is unencoded (`b64` is false) and not valid UTF-8.
 */
export function parseJws<
  ProtectedHeaderSchema extends BaseSchema | undefined = undefined,
  UnprotectedHeaderSchema extends BaseSchema | undefined = undefined,
>(
  options: ParseJwsOptions<ProtectedHeaderSchema, UnprotectedHeaderSchema>
): ParsedJws<ProtectedHeaderSchema, UnprotectedHeaderSchema> {
  const parts =
    typeof options.jws === 'string'
      ? compactJwsParts(options.jws)
      : jsonJwsParts(options.jws, options.signatureIndex ?? 0)

  if (!parts.encodedProtectedHeader) {
    throw new JoseParseError(
      'Unable to parse the JWS, it does not have a protected header. A JWS without a protected header does not integrity protect its own algorithm, and is not supported.'
    )
  }

  const protectedHeaderJson = decodeBase64UrlJsonObject(parts.encodedProtectedHeader, 'JWS protected header')

  if (parts.unprotectedHeader) {
    const duplicates = Object.keys(parts.unprotectedHeader).filter((name) => hasOwn(protectedHeaderJson, name))
    if (duplicates.length > 0) {
      throw new JoseParseError(
        `Unable to parse the JWS, the header parameter(s) ${duplicates.map((name) => `'${name}'`).join(', ')} are present in both the protected and the unprotected header, which must be disjoint`
      )
    }
  }

  // Always validated against the registered JWS header parameters, and only then against the
  // caller's schema: a schema that describes a profile's own parameters must not be able to leave
  // `alg` or `crit` unchecked. What it returns is returned, but every check is made on the registered
  // header, which a schema that drops or changes members cannot affect.
  const registeredHeader = parseWithErrorHandling(
    zJwsProtectedHeader,
    protectedHeaderJson,
    'Invalid JWS protected header',
    JoseValidationError
  )
  const protectedHeader = parseWithErrorHandling(
    options.protectedHeaderSchema ?? zJwsProtectedHeader,
    protectedHeaderJson,
    'Invalid JWS protected header',
    JoseValidationError
  )

  const unprotectedHeader = parts.unprotectedHeader
    ? parseWithErrorHandling(
        options.unprotectedHeaderSchema ?? zJwsUnprotectedHeader,
        parts.unprotectedHeader,
        'Invalid JWS unprotected header',
        JoseValidationError
      )
    : undefined

  // Checked against the registered header rather than the raw JSON, so that `crit` and `b64` are
  // already known to have the shape RFC 7515 gives them.
  assertCriticalHeaderParameters({
    protectedHeader: registeredHeader,
    unprotectedHeader: parts.unprotectedHeader,
    understoodCriticalParameters: options.understoodCriticalParameters,
  })

  const isBase64UrlEncoded = isPayloadBase64UrlEncoded(registeredHeader)

  // RFC 7797 section 5.2: a compact serialization only carries an unencoded payload of printable ASCII
  // other than '.'. A '.' has already split the JWS into more parts.
  const compactPayloadIssue =
    parts.serialization === 'compact' && !isBase64UrlEncoded && parts.serializedPayload !== undefined
      ? unencodedCompactPayloadIssue(parts.serializedPayload)
      : undefined
  if (compactPayloadIssue) throw new JoseParseError(`Unable to parse the JWS. ${compactPayloadIssue}`)

  const { payload, encodedPayload } = resolvePayload({
    serializedPayload: parts.serializedPayload,
    detachedPayload: options.detachedPayload,
    isBase64UrlEncoded,
  })

  return {
    serialization: parts.serialization,
    protectedHeader: protectedHeader as ParsedJws<ProtectedHeaderSchema, UnprotectedHeaderSchema>['protectedHeader'],
    registeredProtectedHeader: registeredHeader,
    unprotectedHeader: unprotectedHeader as ParsedJws<
      ProtectedHeaderSchema,
      UnprotectedHeaderSchema
    >['unprotectedHeader'],
    encodedProtectedHeader: parts.encodedProtectedHeader,
    payload,
    encodedPayload,
    signature: parts.signature,
    signingInput: `${parts.encodedProtectedHeader}.${encodedPayload}`,
    compact: parts.compact,
  }
}

function resolvePayload({
  serializedPayload,
  detachedPayload,
  isBase64UrlEncoded,
}: {
  serializedPayload: string | undefined
  detachedPayload: string | Uint8Array | undefined
  isBase64UrlEncoded: boolean
}): { payload: Uint8Array; encodedPayload: string } {
  if (serializedPayload !== undefined && detachedPayload !== undefined) {
    throw new JoseParseError(
      'A detached payload was provided, but the JWS carries a payload. Only one of the two can be the payload that was signed.'
    )
  }

  if (serializedPayload === undefined && detachedPayload === undefined) {
    throw new JoseParseError(
      'The JWS does not carry a payload and no detached payload was provided, so there is nothing to verify. Pass the payload as `detachedPayload`.'
    )
  }

  if (detachedPayload !== undefined) {
    const payload = typeof detachedPayload === 'string' ? stringToBytes(detachedPayload) : detachedPayload
    return {
      payload,
      encodedPayload: isBase64UrlEncoded ? base64url.encode(payload) : decodeUnencodedPayload(payload),
    }
  }

  const serialized = serializedPayload as string
  return {
    payload: isBase64UrlEncoded ? decodeBase64UrlBytes(serialized, 'JWS payload') : stringToBytes(serialized),
    encodedPayload: serialized,
  }
}
