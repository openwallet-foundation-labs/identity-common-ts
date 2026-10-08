import { JoseCriticalHeaderError } from '../error'
import { hasOwn } from '../utils/object'
import type { JwsProtectedHeader, JwsUnprotectedHeader } from './z-jws'

/**
 * The header parameter names registered by RFC 7515, RFC 7516 and RFC 7518.
 *
 * A producer must not list any of these in `crit`: `crit` exists to mark extensions, and marking a
 * parameter that every implementation already has to understand makes the list meaningless.
 *
 * `b64` (RFC 7797) is deliberately absent, as RFC 7797 requires it to be listed in `crit`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11
 */
const registeredHeaderParameters = new Set([
  'alg',
  'jku',
  'jwk',
  'kid',
  'x5u',
  'x5c',
  'x5t',
  'x5t#S256',
  'typ',
  'cty',
  'crit',
  'enc',
  'zip',
  'epk',
  'apu',
  'apv',
  'iv',
  'tag',
  'p2s',
  'p2c',
])

export interface AssertCriticalHeaderParametersOptions {
  /**
   * The protected header, validated against {@link zJwsProtectedHeader}, which is the only place
   * `crit` may appear.
   *
   * Taking a validated header rather than the raw JSON is what keeps the shape rules — a non-empty
   * array of non-empty strings, a boolean `b64` — in the schema, where they are expressed once and
   * where a reader looks for them, instead of being restated here.
   */
  protectedHeader: JwsProtectedHeader

  /** The unprotected header, if the serialization has one. */
  unprotectedHeader?: JwsUnprotectedHeader

  /**
   * The extension header parameters the caller understands and processes.
   *
   * A JWS that marks a parameter critical is rejected unless it is named here, because accepting it
   * would mean ignoring something the producer said must not be ignored.
   */
  understoodCriticalParameters?: ReadonlyArray<string>
}

/**
 * Verifies the `crit` header parameter of a JWS.
 *
 * @throws JoseCriticalHeaderError if `crit` is invalid, or names a parameter that is not understood.
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11
 */
export function assertCriticalHeaderParameters({
  protectedHeader,
  unprotectedHeader,
  understoodCriticalParameters = [],
}: AssertCriticalHeaderParametersOptions): void {
  // `crit` says which parameters must not be ignored, so it must not itself be something an
  // attacker can add or remove: it is only meaningful when it is integrity protected.
  if (unprotectedHeader && hasOwn(unprotectedHeader, 'crit')) {
    throw new JoseCriticalHeaderError(
      `The 'crit' header parameter is present in the unprotected header, where it is not integrity protected and therefore not valid`
    )
  }

  const crit = protectedHeader.crit
  if (crit === undefined) return

  const understood = new Set(understoodCriticalParameters)

  for (const name of crit) {
    if (registeredHeaderParameters.has(name)) {
      throw new JoseCriticalHeaderError(
        `The 'crit' header parameter lists '${name}', which is a registered header parameter and must not be listed`
      )
    }

    // A parameter can be marked critical in the protected header while being carried in the
    // unprotected one, so both are looked at.
    if (!hasOwn(protectedHeader, name) && !(unprotectedHeader && hasOwn(unprotectedHeader, name))) {
      throw new JoseCriticalHeaderError(
        `The 'crit' header parameter lists '${name}', but the header does not contain that parameter`
      )
    }

    if (!understood.has(name)) {
      throw new JoseCriticalHeaderError(
        `The 'crit' header parameter lists '${name}', which is not understood. A JWS that marks a header parameter as critical can only be accepted when that parameter is processed.`
      )
    }
  }
}

/**
 * Whether the payload of a JWS is base64url encoded in the serialization, per the `b64` header
 * parameter.
 *
 * RFC 7797 requires `b64` to be listed in `crit` whenever it is used, so that an implementation that
 * does not know about unencoded payloads rejects the JWS rather than verifying the wrong bytes.
 *
 * @throws JoseCriticalHeaderError if `b64` is used without being marked critical.
 * @see https://www.rfc-editor.org/rfc/rfc7797#section-6
 */
export function isPayloadBase64UrlEncoded(protectedHeader: JwsProtectedHeader): boolean {
  const b64 = protectedHeader.b64
  if (b64 === undefined) return true

  if (!protectedHeader.crit?.includes('b64')) {
    throw new JoseCriticalHeaderError(
      `The 'b64' header parameter is used, but is not listed in the 'crit' header parameter, which RFC 7797 requires`
    )
  }

  return b64
}
