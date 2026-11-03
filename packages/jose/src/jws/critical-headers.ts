import { ValidationIssues } from '@owf/identity-common'
import { JoseValidationError, type JoseValidationIssue } from '../error'
import { hasOwn } from '../utils/object'
import type { JwsProtectedHeader, JwsUnprotectedHeader } from './z-jws'

/**
 * The header parameters of RFC 7515, RFC 7516 and RFC 7518, which `crit` must not list. `b64` is not
 * one of them: RFC 7797 requires it in `crit`.
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
  /** The protected header, validated against {@link zJwsProtectedHeader}, so the shape of `crit` is checked. */
  protectedHeader: JwsProtectedHeader

  /** The unprotected header, if the serialization has one. */
  unprotectedHeader?: JwsUnprotectedHeader

  /** The extension header parameters the caller processes. A JWS that marks another one critical is rejected. */
  understoodCriticalParameters?: ReadonlyArray<string>
}

/**
 * Verifies the `crit` header parameter of a JWS.
 *
 * @throws JoseValidationError with an `invalid_crit` or `unsupported_crit` issue for each way `crit`
 * is invalid, or names a parameter that is not understood.
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11
 */
export function assertCriticalHeaderParameters({
  protectedHeader,
  unprotectedHeader,
  understoodCriticalParameters = [],
}: AssertCriticalHeaderParametersOptions): void {
  const issues = new ValidationIssues<JoseValidationIssue['code']>()

  // `crit` is only meaningful when it is integrity protected
  if (unprotectedHeader && hasOwn(unprotectedHeader, 'crit')) {
    issues.add({
      code: 'invalid_crit',
      path: ['crit'],
      message: `The 'crit' header parameter is present in the unprotected header, where it is not integrity protected and therefore not valid`,
    })
  }

  const understood = new Set(understoodCriticalParameters)

  protectedHeader.crit?.forEach((name, index) => {
    const path = ['crit', index]
    if (registeredHeaderParameters.has(name)) {
      issues.add({
        code: 'invalid_crit',
        path,
        message: `The 'crit' header parameter lists '${name}', which is a registered header parameter and must not be listed`,
        context: { parameter: name },
      })
    }
    // A parameter marked critical can be carried in the unprotected header
    else if (!hasOwn(protectedHeader, name) && !(unprotectedHeader && hasOwn(unprotectedHeader, name))) {
      issues.add({
        code: 'invalid_crit',
        path,
        message: `The 'crit' header parameter lists '${name}', but the header does not contain that parameter`,
        context: { parameter: name },
      })
    } else if (!understood.has(name)) {
      issues.add({
        code: 'unsupported_crit',
        path,
        message: `The 'crit' header parameter lists '${name}', which is not understood. A JWS that marks a header parameter as critical can only be accepted when that parameter is processed.`,
        context: { parameter: name, understood: [...understood] },
      })
    }
  })

  if (issues.issues.length) throw new JoseValidationError('Invalid JWS crit header parameter', issues.issues)
}

/**
 * Whether the payload of a JWS is base64url encoded, per `b64`. RFC 7797 requires `b64` to be listed
 * in `crit`.
 *
 * @throws JoseValidationError with an `invalid_crit` issue if `b64` is used without being marked critical.
 * @see https://www.rfc-editor.org/rfc/rfc7797#section-6
 */
export function isPayloadBase64UrlEncoded(protectedHeader: JwsProtectedHeader): boolean {
  const b64 = protectedHeader.b64
  if (b64 === undefined) return true

  if (!protectedHeader.crit?.includes('b64')) {
    throw new JoseValidationError('Invalid JWS crit header parameter', [
      {
        severity: 'error',
        code: 'invalid_crit',
        path: ['crit'],
        message: `The 'b64' header parameter is used, but is not listed in the 'crit' header parameter, which RFC 7797 requires`,
      },
    ])
  }

  return b64
}
