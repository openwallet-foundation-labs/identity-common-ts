import { IdentityException } from '@owf/identity-common'

/**
 * Base error class for the CBOR encoding and decoding in this package.
 *
 * Extends `IdentityException` so that a caller can catch every error raised by the identity-common
 * packages in one place.
 */
export class CborError extends IdentityException {
  // NOTE: declared explicitly rather than passing `{ cause }` to `super`, as the
  // project targets ES2020 and `Error.cause` was only added in ES2022.
  public readonly cause?: unknown

  constructor(message: string = new.target.name, options?: { cause?: unknown; details?: unknown }) {
    super(message, options?.details)
    this.name = new.target.name
    this.cause = options?.cause
  }
}

export class CborDecodeError extends CborError {}
export class CborEncodeError extends CborError {}
