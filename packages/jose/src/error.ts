import { IdentityError } from '@owf/identity-common'

/**
 * Base error class for `@owf/jose`.
 *
 * Extends `IdentityError` so that a caller can catch every error raised by the identity-common
 * packages in one place, and carries an optional `cause` — declared explicitly rather than passed
 * to `super`, as the project targets ES2020 and `Error.cause` was only added in ES2022.
 */
export class JoseError extends IdentityError {
  public readonly cause?: unknown

  constructor(message: string, options?: { cause?: unknown; details?: unknown }) {
    super(message, options?.details)

    this.cause = options?.cause
  }
}

/**
 * A token is not well-formed: the serialization does not have the expected structure, or a part of
 * it is not valid base64url, UTF-8 or JSON.
 *
 * The message deliberately does not include the offending input, so that a token is not echoed into
 * logs by accident.
 */
export class JoseParseError extends JoseError {}

/**
 * A structure is well-formed, but does not validate against the schema it was parsed with.
 *
 * A subclass of {@link JoseParseError}: a token that does not satisfy the schema of the token type
 * it claims to be is not a token of that type, so a caller that only wants to know whether it was
 * handed something usable catches the one class.
 */
export class JoseValidationError extends JoseParseError {}

/**
 * A token is well-formed, but does not verify: its signature, the key that made it, the algorithm it
 * uses, or the claims in it.
 *
 * The subclasses say which of those it was. Catch this one to treat every way a token can fail
 * verification alike, which is what a verifier usually wants — a token that does not verify is not
 * to be acted on, whichever part of it was wrong.
 */
export class JoseVerificationError extends JoseError {}

/** The signature over a JWS does not verify, or the verification callback rejected it. */
export class JoseSignatureVerificationError extends JoseVerificationError {}

/** The claim a {@link JoseClaimVerificationError} is about, and what was wrong with it. */
export interface JoseClaimVerificationErrorOptions {
  cause?: unknown
  details?: unknown

  /** The claim that did not verify, e.g. `exp` or `aud`. */
  claim?: string

  /**
   * What was wrong with it, as a value a caller can branch on rather than having to read the
   * message.
   */
  reason?: JoseClaimVerificationReason
}

export type JoseClaimVerificationReason =
  /** The claim is required, but the token does not carry it. */
  | 'missing'
  /** The claim is present, but not the value that was expected. */
  | 'mismatch'
  /** `exp`: the token is no longer valid. */
  | 'expired'
  /** `nbf` or `iat`: the token is not valid yet. */
  | 'not-yet-valid'
  /** The claim is present, but cannot be interpreted — a `exp` that is not a NumericDate, say. */
  | 'invalid'

/**
 * A claim required by the profile the token is verified against is missing, a claim does not match
 * the value it was expected to have, or the token is outside its validity window.
 *
 * `claim` and `reason` say which claim failed and how, so a caller can map the failure onto its own
 * error codes without matching on the message.
 */
export class JoseClaimVerificationError extends JoseVerificationError {
  /** The claim that did not verify, e.g. `exp` or `aud`. */
  public readonly claim?: string

  /** What was wrong with it. */
  public readonly reason?: JoseClaimVerificationReason

  constructor(message: string, options?: JoseClaimVerificationErrorOptions) {
    super(message, options)

    this.claim = options?.claim
    this.reason = options?.reason
  }
}

/** The `alg` of a token is not among the algorithms the caller allows. */
export class JoseAlgorithmNotAllowedError extends JoseVerificationError {}

/** The `crit` header parameter is invalid, or names a parameter that is not understood. */
export class JoseCriticalHeaderError extends JoseVerificationError {}

/** The key that identifies the signer cannot be determined from the token, or is ambiguous. */
export class JoseSignerError extends JoseVerificationError {}

/** The token uses a feature that this library does not implement. */
export class JoseNotSupportedError extends JoseError {}

/**
 * The calling code passed something this library cannot act on: an option outside the values it can
 * take, options that contradict each other, or a signing callback result that does not satisfy the
 * contract of the callback. A verification callback that reports success without a usable key fails
 * verification instead, with a {@link JoseSignatureVerificationError}.
 *
 * Unlike the other errors, this one says nothing about a token: it is a mistake in the calling code.
 * It is thrown rather than letting a check pass that cannot be made — with a clock skew of `NaN`,
 * every comparison against the current time would.
 */
export class JoseInvalidArgumentError extends JoseError {}
