/**
 * JAdES Error
 *
 * Custom error for JAdES-related failures.
 */

import { IdentityError } from '@owf/identity-common'

export class JadesError extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, JadesError.prototype)
    this.name = 'JadesError'
  }
}
