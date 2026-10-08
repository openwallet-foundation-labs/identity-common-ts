import { IdentityError } from '@owf/identity-common'

export interface Oauth2ErrorOptions {
  cause?: unknown

  /** Structured detail about the failure, e.g. the zod issues of a schema that did not match. */
  details?: unknown
}

/**
 * Base error class for `@openid4vc/oauth2`.
 *
 * Extends `IdentityError`, the base every error in these packages shares, so that a caller can
 * catch all of them in one place, and so that an error can be wrapped by passing it as `cause`
 * rather than by copying its message.
 */
export class Oauth2Error extends IdentityError {
  // NOTE: declared explicitly rather than passing `{ cause }` to `super`, as the project targets
  // ES2020 and `Error.cause` was only added in ES2022.
  public readonly cause?: unknown

  public constructor(message?: string, options?: Oauth2ErrorOptions) {
    super(message ?? 'Unknown error occurred.', options?.details)

    // `new.target` is the class that was constructed, so every subclass is named after itself.
    this.name = new.target.name
    this.cause = options?.cause
  }
}
