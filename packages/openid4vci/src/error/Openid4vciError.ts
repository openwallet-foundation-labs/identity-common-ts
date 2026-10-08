import { IdentityError } from '@owf/identity-common'

export interface Openid4vciErrorOptions {
  cause?: unknown

  /** Structured detail about the failure, e.g. the zod issues of a schema that did not match. */
  details?: unknown
}

/**
 * Base error class for `@openid4vc/openid4vci`.
 *
 * Extends `IdentityError` for the same reason `Oauth2Error` does: one base to catch, and a
 * `cause` chain instead of messages copied from one error into the next.
 */
export class Openid4vciError extends IdentityError {
  // NOTE: declared explicitly rather than passing `{ cause }` to `super`, as the project targets
  // ES2020 and `Error.cause` was only added in ES2022.
  public readonly cause?: unknown

  public constructor(message?: string, options?: Openid4vciErrorOptions) {
    super(message ?? 'Unknown error occurred.', options?.details)

    this.name = new.target.name
    this.cause = options?.cause
  }
}
