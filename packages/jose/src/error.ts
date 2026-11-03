import {
  type CommonValidationCode,
  IdentityError,
  type SchemaValidationCode,
  ValidationError,
  type ValidationIssueOf,
} from '@owf/identity-common'

/**
 * Base error class for `@owf/jose`. `cause` is declared here, as `Error.cause` is ES2022 and the
 * project targets ES2020.
 */
export class JoseError extends IdentityError {
  public readonly cause?: unknown

  constructor(message: string, options?: { cause?: unknown; details?: unknown }) {
    super(message, options?.details)

    this.cause = options?.cause
  }
}

/**
 * A token is not well-formed: a wrong structure, or a part that is not valid base64url, UTF-8 or
 * JSON. The message never includes the input, so a token is not logged by accident.
 */
export class JoseParseError extends JoseError {}

/** An issue of a JOSE structure that does not validate, with a schema or common code */
export type JoseValidationIssue = ValidationIssueOf<CommonValidationCode | SchemaValidationCode>

/**
 * A structure is well-formed but does not validate: its schema, `crit` or claims. Like the validation
 * errors of the other packages, it extends `ValidationError`, not {@link JoseError}.
 */
export class JoseValidationError extends ValidationError<JoseValidationIssue> {}

/**
 * A token is well-formed but does not verify: its signature, signer or algorithm. The subclasses say
 * which. Claims that do not verify throw a {@link JoseValidationError}.
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
 * A mistake in the calling code, not in a token: an invalid or contradicting option, or a signing
 * callback result that breaks the contract of the callback.
 */
export class JoseInvalidArgumentError extends JoseError {}
