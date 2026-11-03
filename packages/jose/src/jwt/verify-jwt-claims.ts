import { secondsToDate, ValidationIssues } from '@owf/identity-common'
import { JoseInvalidArgumentError, JoseValidationError, type JoseValidationIssue } from '../error'
import { hasOwn } from '../utils/object'
import type { JwtPayload } from './z-jwt'

/**
 * The options {@link verifyJwtClaims} takes.
 *
 * These are the checks that cannot be expressed in a schema, because they compare the token against
 * something outside of it: the current time, the audience the verifier is, the nonce it issued.
 * Everything that follows from the token alone — which claims a token type requires, and what shape
 * they have — belongs in the payload schema instead.
 */
export interface VerifyJwtClaimsOptions {
  /** The time the token is verified at. Defaults to the current time. Must be a valid date. */
  now?: Date

  /**
   * Clock tolerance applied to `exp`, `nbf` and `iat`, in seconds. Defaults to 30, which keeps a
   * token that only just expired — or that was issued a moment ago by a slightly fast clock —
   * usable across the small clock differences typical between issuer and verifier.
   *
   * Must be a finite number of at least 0: anything else is rejected rather than letting a time
   * check pass that was never made.
   */
  skewSeconds?: number

  /**
   * The claims that must be present. A claim listed here is rejected when absent; a claim that is
   * absent and not listed is simply not checked.
   *
   * A claim whose value is `null` counts as present: `null` is a value the issuer put there, unlike
   * a claim that is not in the token at all.
   */
  requiredClaims?: ReadonlyArray<string>

  /**
   * The value(s) `iss` is accepted with.
   *
   * A token that does not carry the claim at all is rejected too: a claim that is absent does not
   * hold the value the caller said it expects.
   */
  expectedIssuer?: string | string[]

  /** The value(s) `sub` is accepted with. See {@link expectedIssuer} for an absent claim. */
  expectedSubject?: string | string[]

  /**
   * The value(s) `aud` is accepted with. The token is accepted when any of its audiences is one of
   * these. See {@link expectedIssuer} for an absent claim.
   */
  expectedAudience?: string | string[]

  /** The value `nonce` is accepted with. See {@link expectedIssuer} for an absent claim. */
  expectedNonce?: string

  /**
   * When false, `exp` is not looked at. Its presence is not checked either way — list it in
   * {@link requiredClaims} to require it.
   */
  checkExpirationTime?: boolean

  /** When false, `nbf` is not looked at. See {@link checkExpirationTime} for its presence. */
  checkNotBefore?: boolean

  /** When false, `iat` is not looked at. See {@link checkExpirationTime} for its presence. */
  checkIssuedAt?: boolean

  /**
   * The maximum age of the token in seconds, counted from `iat`. For a token that proves something
   * happened recently — a key binding JWT, a DPoP proof — rather than one that states its own
   * expiry.
   *
   * A token that carries no `iat` is rejected when this is set: a token that does not say when it
   * was issued cannot be shown to be recent. The skew applies, as it does to `exp`. Must be a finite
   * number of at least 0.
   */
  maxAgeSeconds?: number

  /** Message of the error thrown when a claim does not verify. */
  errorMessage?: string
}

const asArray = (value: string | string[]) => (Array.isArray(value) ? value : [value])
const isNonNegativeFiniteNumber = (value: number) => Number.isFinite(value) && value >= 0
const quoted = (values: ReadonlyArray<string>) => values.map((value) => `'${value}'`).join(', ')

type ClaimIssues = ValidationIssues<JoseValidationIssue['code']>

/**
 * Verifies the claims of a JWT: that the claims the caller requires are present, that `iss`, `sub`,
 * `aud` and `nonce` are the expected ones, and that the token is within its validity window.
 *
 * Which claims a JWT must carry, and what they must contain, is decided by the token type rather
 * than by RFC 7519, so nothing is required unless `requiredClaims` says so.
 *
 * This checks the claims only. The signature over them is verified separately — `verifyJwt` does
 * both, and is what a verifier wants.
 *
 * @throws JoseValidationError with an issue for each claim that does not verify: `claim_missing` for a
 *   required claim that is absent, `claim_value_mismatch` for one that is not the expected value,
 *   `expired` or `not_yet_valid` for a token outside its validity window, and `invalid_type` for a
 *   time claim that is not a NumericDate.
 * @throws JoseInvalidArgumentError if `now` is not a valid date, or `skewSeconds` or `maxAgeSeconds`
 *   is not a finite number of at least 0.
 */
export function verifyJwtClaims(
  payload: JwtPayload,
  {
    now = new Date(),
    skewSeconds = 30,
    requiredClaims,
    expectedIssuer,
    expectedSubject,
    expectedAudience,
    expectedNonce,
    checkExpirationTime = true,
    checkNotBefore = true,
    checkIssuedAt = true,
    maxAgeSeconds,
    errorMessage = 'Error during verification of the JWT claims.',
  }: VerifyJwtClaimsOptions = {}
): void {
  // Every time check compares against `now` shifted by the skew. With `NaN` in either, every such
  // comparison is false, which accepts the token rather than rejecting it. A negative skew or maximum
  // age means nothing, and an infinite one accepts any token.
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new JoseInvalidArgumentError(`${errorMessage} The 'now' option must be a valid date.`)
  }
  if (!isNonNegativeFiniteNumber(skewSeconds)) {
    throw new JoseInvalidArgumentError(
      `${errorMessage} The 'skewSeconds' option must be a finite number of at least 0, but is '${skewSeconds}'.`
    )
  }
  if (maxAgeSeconds !== undefined && !isNonNegativeFiniteNumber(maxAgeSeconds)) {
    throw new JoseInvalidArgumentError(
      `${errorMessage} The 'maxAgeSeconds' option must be a finite number of at least 0, but is '${maxAgeSeconds}'.`
    )
  }

  // The time claims are compared as numbers of seconds rather than as dates, so that a NumericDate
  // outside the range of a `Date` still orders: an `exp` of 9999999999999 does not expire.
  const nowSeconds = now.getTime() / 1000
  const issues: ClaimIssues = new ValidationIssues()

  for (const claim of requiredClaims ?? []) {
    if (!hasOwn(payload, claim)) addClaimMissing(issues, claim, `The token has no '${claim}' claim, which is required`)
  }

  verifyClaimMatches(issues, 'iss', payload.iss, expectedIssuer)
  verifyClaimMatches(issues, 'sub', payload.sub, expectedSubject)
  verifyClaimMatches(issues, 'nonce', payload.nonce, expectedNonce)
  verifyAudienceMatches(issues, payload.aud, expectedAudience)

  // Each time claim is read once, so a claim that is not a NumericDate gives one issue.
  const expirationTime = checkExpirationTime ? numericDate(issues, 'exp', payload.exp) : undefined
  const notBefore = checkNotBefore ? numericDate(issues, 'nbf', payload.nbf) : undefined
  const issuedAt = checkIssuedAt || maxAgeSeconds !== undefined ? numericDate(issues, 'iat', payload.iat) : undefined

  // `exp` is the first instant the token is no longer valid (RFC 7519 says a token must not be
  // accepted "on or after" it), so the comparison is inclusive. It is an upper bound shifted forward
  // by the skew: a token that expired within the tolerance is still accepted.
  if (expirationTime !== undefined && expirationTime + skewSeconds <= nowSeconds) {
    issues.add({
      code: 'expired',
      path: ['exp'],
      message: `The 'exp' claim '${formatNumericDate(expirationTime)}' is in the past (compared to '${now.toISOString()}')`,
      context: { expiredAt: secondsToDate(expirationTime) },
    })
  }

  if (notBefore !== undefined) verifyClaimNotInFuture(issues, 'nbf', notBefore, now, skewSeconds)
  if (checkIssuedAt && issuedAt !== undefined) verifyClaimNotInFuture(issues, 'iat', issuedAt, now, skewSeconds)

  if (maxAgeSeconds !== undefined) {
    if (payload.iat === undefined) {
      addClaimMissing(
        issues,
        'iat',
        `The token has no 'iat' claim, which is required to verify that it is at most ${maxAgeSeconds} seconds old`
      )
    } else if (issuedAt !== undefined && issuedAt + maxAgeSeconds + skewSeconds < nowSeconds) {
      issues.add({
        code: 'expired',
        path: ['iat'],
        message: `The 'iat' claim '${formatNumericDate(issuedAt)}' is more than ${maxAgeSeconds} seconds in the past (compared to '${now.toISOString()}')`,
        context: { expiredAt: secondsToDate(issuedAt + maxAgeSeconds) },
      })
    }
  }

  if (issues.issues.length) throw new JoseValidationError(errorMessage, issues.issues)
}

/** A required claim is absent. A claim is reported once, however many checks need it. */
function addClaimMissing(issues: ClaimIssues, claim: string, message: string): void {
  const reported = issues.issues.some((issue) => issue.code === 'claim_missing' && issue.path[0] === claim)
  if (!reported) issues.add({ code: 'claim_missing', path: [claim], message })
}

/**
 * The NumericDate a time claim holds, or `undefined` when the token does not carry the claim or it is
 * not a NumericDate.
 *
 * A claim that is present but is not a finite number gives an issue rather than being skipped: it
 * cannot be compared against `now` (with `NaN` every comparison would be false, which would accept
 * the token), and skipping it would accept a token whose validity window was never verified. A
 * payload parsed with `zJwtPayload` cannot get here, but one that reached the caller unvalidated can.
 *
 * Any finite number is a NumericDate, including one outside the range a `Date` can hold: it is
 * compared as a number of seconds.
 */
function numericDate(issues: ClaimIssues, claim: string, value: unknown): number | undefined {
  if (value === undefined) return undefined

  if (typeof value !== 'number' || !Number.isFinite(value)) {
    issues.add({
      code: 'invalid_type',
      path: [claim],
      message: `The '${claim}' claim '${String(value)}' is not a NumericDate`,
      context: { expected: 'number' },
    })
    return undefined
  }

  return value
}

/**
 * A NumericDate as it is printed in an issue: as a date where it has one, and as the number it is
 * where it is outside the range of a `Date`.
 */
function formatNumericDate(seconds: number): string {
  const date = secondsToDate(seconds)
  return Number.isNaN(date.getTime()) ? String(seconds) : date.toISOString()
}

function verifyClaimMatches(
  issues: ClaimIssues,
  claim: string,
  value: unknown,
  expected: string | string[] | undefined
): void {
  if (expected === undefined) return

  const expectedValues = asArray(expected)

  // An absent claim is a mismatch rather than something to skip: a token that does not say who
  // issued it is not a token issued by the expected issuer.
  if (value === undefined) {
    addClaimMissing(
      issues,
      claim,
      `The token has no '${claim}' claim, which is required to match the expected value ${quoted(expectedValues)}`
    )
  } else if (typeof value !== 'string' || !expectedValues.includes(value)) {
    issues.add({
      code: 'claim_value_mismatch',
      path: [claim],
      message: `The '${claim}' claim '${String(value)}' does not match the expected value ${quoted(expectedValues)}`,
      context: { expected: expectedValues, actual: value },
    })
  }
}

/** `aud` may hold several audiences, and the token is for us as soon as one of them is expected. */
function verifyAudienceMatches(
  issues: ClaimIssues,
  audience: string | string[] | undefined,
  expected: string | string[] | undefined
): void {
  if (expected === undefined) return

  const expectedValues = asArray(expected)

  // See `verifyClaimMatches`: a token carrying no audience is not a token for this audience.
  if (audience === undefined) {
    addClaimMissing(
      issues,
      'aud',
      `The token has no 'aud' claim, which is required to match the expected value ${quoted(expectedValues)}`
    )
    return
  }

  const audiences = asArray(audience)

  if (!audiences.some((value) => expectedValues.includes(value))) {
    issues.add({
      code: 'claim_value_mismatch',
      path: ['aud'],
      message: `The 'aud' claim ${quoted(audiences)} does not match the expected value ${quoted(expectedValues)}`,
      context: { expected: expectedValues, actual: audience },
    })
  }
}

/**
 * `nbf` and `iat` are lower bounds on the validity window, so they are shifted back by the skew: a
 * token whose validity starts within the tolerance is already accepted.
 */
function verifyClaimNotInFuture(
  issues: ClaimIssues,
  claim: string,
  seconds: number,
  now: Date,
  skewSeconds: number
): void {
  if (seconds - skewSeconds > now.getTime() / 1000) {
    issues.add({
      code: 'not_yet_valid',
      path: [claim],
      message: `The '${claim}' claim '${formatNumericDate(seconds)}' is in the future (compared to '${now.toISOString()}')`,
      context: { validFrom: secondsToDate(seconds) },
    })
  }
}
