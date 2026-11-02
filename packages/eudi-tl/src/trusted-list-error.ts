import { IdentityError, validationErrorMessage } from '@owf/identity-common'
import type { TrustedListValidationIssue } from './validate'

/**
 * Base error for all trusted-list processing failures.
 *
 * Extends `IdentityError`, the base every error in these packages shares.
 */
export class TrustedListError extends IdentityError {
  // NOTE: declared explicitly rather than passing `{ cause }` to `super`, as the
  // project targets ES2020 and `Error.cause` was only added in ES2022.
  public readonly cause?: unknown

  constructor(message: string, options?: { cause?: unknown }) {
    super(message)
    this.name = new.target.name
    this.cause = options?.cause
  }
}

/**
 * The XML could not be parsed as an ETSI TS 119 612 `TrustServiceStatusList`.
 */
export class TrustedListParseError extends TrustedListError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'TrustedListParseError'
  }
}

/**
 * The parsed list does not conform to the TS 119 612 schema or to a profile, with the
 * `issues` of the validation. The message lists the errors among them.
 */
export class TrustedListValidationError extends TrustedListParseError {
  readonly issues: TrustedListValidationIssue[]

  constructor(message: string, issues: TrustedListValidationIssue[]) {
    super(validationErrorMessage(message, issues))
    this.name = 'TrustedListValidationError'
    this.issues = issues
  }
}

/**
 * The trusted list's own XAdES/XMLDSig signature is missing, invalid, or does
 * not match a configured trust anchor. Callers MUST treat this as fail-closed:
 * a trusted list whose authenticity cannot be established must not be used to
 * trust credentials.
 */
export class TrustedListSignatureError extends TrustedListError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'TrustedListSignatureError'
  }
}
