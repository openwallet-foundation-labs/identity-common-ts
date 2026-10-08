import { secondsToDate } from '@owf/identity-common'
import { JoseClaimVerificationError, JoseInvalidArgumentError } from '../error'
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

  /** Prefix for the error thrown when a claim does not verify. */
  errorMessage?: string
}

const asArray = (value: string | string[]) => (Array.isArray(value) ? value : [value])
const isNonNegativeFiniteNumber = (value: number) => Number.isFinite(value) && value >= 0
const quoted = (values: ReadonlyArray<string>) => values.map((value) => `'${value}'`).join(', ')

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
 * @throws JoseClaimVerificationError if a required claim is missing, a claim does not match what was
 *   expected, or the token is outside its validity window.
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

  for (const claim of requiredClaims ?? []) {
    if (!hasOwn(payload, claim)) {
      throw new JoseClaimVerificationError(`${errorMessage} The token has no '${claim}' claim, which is required.`, {
        claim,
        reason: 'missing',
      })
    }
  }

  verifyClaimMatches('iss', payload.iss, expectedIssuer, errorMessage)
  verifyClaimMatches('sub', payload.sub, expectedSubject, errorMessage)
  verifyClaimMatches('nonce', payload.nonce, expectedNonce, errorMessage)
  verifyAudienceMatches(payload.aud, expectedAudience, errorMessage)

  // `exp` is the first instant the token is no longer valid — RFC 7519 says a token must not be
  // accepted "on or after" it — so the comparison is inclusive. It is an upper bound shifted forward
  // by the skew: a token that expired within the tolerance is still accepted.
  if (checkExpirationTime) {
    const expirationTime = numericDate('exp', payload.exp, errorMessage)
    if (expirationTime !== undefined && expirationTime + skewSeconds <= nowSeconds) {
      throw new JoseClaimVerificationError(
        `${errorMessage} The 'exp' claim '${formatNumericDate(expirationTime)}' is in the past (compared to '${now.toISOString()}'), and therefore not valid.`,
        { claim: 'exp', reason: 'expired' }
      )
    }
  }

  if (checkNotBefore) verifyClaimNotInFuture('nbf', payload.nbf, now, skewSeconds, errorMessage)
  if (checkIssuedAt) verifyClaimNotInFuture('iat', payload.iat, now, skewSeconds, errorMessage)

  if (maxAgeSeconds !== undefined) {
    const issuedAt = numericDate('iat', payload.iat, errorMessage)
    if (issuedAt === undefined) {
      throw new JoseClaimVerificationError(
        `${errorMessage} The token has no 'iat' claim, which is required to verify that it is at most ${maxAgeSeconds} seconds old.`,
        { claim: 'iat', reason: 'missing' }
      )
    }

    if (issuedAt + maxAgeSeconds + skewSeconds < nowSeconds) {
      throw new JoseClaimVerificationError(
        `${errorMessage} The 'iat' claim '${formatNumericDate(issuedAt)}' is more than ${maxAgeSeconds} seconds in the past (compared to '${now.toISOString()}'), and therefore too old.`,
        { claim: 'iat', reason: 'expired' }
      )
    }
  }
}

/**
 * The NumericDate a time claim holds, or `undefined` when the token does not carry the claim.
 *
 * A claim that is present but is not a finite number is rejected rather than skipped: it cannot be
 * compared against `now` — with `NaN` every comparison would be false, which would accept the token —
 * and skipping it would accept a token whose validity window was never verified. A payload parsed
 * with `zJwtPayload` cannot get here, but one that reached the caller unvalidated can.
 *
 * Any finite number is a NumericDate, including one outside the range a `Date` can hold: it is
 * compared as a number of seconds.
 */
function numericDate(claim: string, value: unknown, errorMessage: string): number | undefined {
  if (value === undefined) return undefined

  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new JoseClaimVerificationError(
      `${errorMessage} The '${claim}' claim '${String(value)}' is not a NumericDate, and therefore cannot be verified.`,
      { claim, reason: 'invalid' }
    )
  }

  return value
}

/**
 * A NumericDate as it is printed in an error: as a date where it has one, and as the number it is
 * where it is outside the range of a `Date`.
 */
function formatNumericDate(seconds: number): string {
  const date = secondsToDate(seconds)
  return Number.isNaN(date.getTime()) ? String(seconds) : date.toISOString()
}

function verifyClaimMatches(
  claim: string,
  value: unknown,
  expected: string | string[] | undefined,
  errorMessage: string
): void {
  if (expected === undefined) return

  const expectedValues = asArray(expected)

  // An absent claim is a mismatch rather than something to skip: a token that does not say who
  // issued it is not a token issued by the expected issuer.
  if (value === undefined) {
    throw new JoseClaimVerificationError(
      `${errorMessage} The token has no '${claim}' claim, which is required to match the expected value ${quoted(expectedValues)}.`,
      { claim, reason: 'missing' }
    )
  }

  if (typeof value !== 'string' || !expectedValues.includes(value)) {
    throw new JoseClaimVerificationError(
      `${errorMessage} The '${claim}' claim '${String(value)}' does not match the expected value ${quoted(expectedValues)}.`,
      { claim, reason: 'mismatch' }
    )
  }
}

/** `aud` may hold several audiences, and the token is for us as soon as one of them is expected. */
function verifyAudienceMatches(
  audience: string | string[] | undefined,
  expected: string | string[] | undefined,
  errorMessage: string
): void {
  if (expected === undefined) return

  const expectedValues = asArray(expected)

  // See `verifyClaimMatches`: a token carrying no audience is not a token for this audience.
  if (audience === undefined) {
    throw new JoseClaimVerificationError(
      `${errorMessage} The token has no 'aud' claim, which is required to match the expected value ${quoted(expectedValues)}.`,
      { claim: 'aud', reason: 'missing' }
    )
  }

  const audiences = asArray(audience)

  if (!audiences.some((value) => expectedValues.includes(value))) {
    throw new JoseClaimVerificationError(
      `${errorMessage} The 'aud' claim ${quoted(audiences)} does not match the expected value ${quoted(expectedValues)}.`,
      { claim: 'aud', reason: 'mismatch' }
    )
  }
}

/**
 * `nbf` and `iat` are lower bounds on the validity window, so they are shifted back by the skew: a
 * token whose validity starts within the tolerance is already accepted.
 */
function verifyClaimNotInFuture(
  claim: string,
  value: unknown,
  now: Date,
  skewSeconds: number,
  errorMessage: string
): void {
  const seconds = numericDate(claim, value, errorMessage)
  if (seconds === undefined) return

  if (seconds - skewSeconds > now.getTime() / 1000) {
    throw new JoseClaimVerificationError(
      `${errorMessage} The '${claim}' claim '${formatNumericDate(seconds)}' is in the future (compared to '${now.toISOString()}'), and therefore not valid.`,
      { claim, reason: 'not-yet-valid' }
    )
  }
}
