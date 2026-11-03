/**
 * JAdES Error
 *
 * Custom error for JAdES-related failures.
 */

import { IdentityError } from '@owf/identity-common'

export class JAdESError extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, JAdESError.prototype)
    this.name = 'JAdESError'
  }
}
