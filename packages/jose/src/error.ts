import {
  type CommonValidationCode,
  IdentityError,
  type SchemaValidationCode,
  ValidationError,
  type ValidationIssueOf,
} from '@owf/identity-common'

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

/** An issue of a JOSE structure that does not validate, with a schema or common code */
export type JoseValidationIssue = ValidationIssueOf<CommonValidationCode | SchemaValidationCode>

/**
 * A structure is well-formed, but does not validate, with the `issues` of the validation: it does
 * not match the schema it was parsed with, its `crit` is invalid (`invalid_crit`, `unsupported_crit`),
 * or a claim does not verify (e.g. `expired`, `claim_value_mismatch`). Like the validation errors of
 * the other packages, it extends the `ValidationError` of `@owf/identity-common`, not {@link JoseError}.
 */
export class JoseValidationError extends ValidationError<JoseValidationIssue> {}

/**
 * A token is well-formed, but does not verify: its signature, the key that made it, or the algorithm
 * it uses. Claims that do not verify throw a {@link JoseValidationError} with the `issues` of the
 * claims.
 *
 * The subclasses say which of those it was. Catch this one to treat every way a token can fail
 * verification alike, which is what a verifier usually wants — a token that does not verify is not
 * to be acted on, whichever part of it was wrong.
 */
export class JoseVerificationError extends JoseError {}

/** The signature over a JWS does not verify, or the verification callback rejected it. */
export class JoseSignatureVerificationError extends JoseVerificationError {}

/** The `alg` of a token is not among the algorithms the caller allows. */
export class JoseAlgorithmNotAllowedError extends JoseVerificationError {}

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
