import { IdentityError } from './identity-error'

/**
 * IdentityCommonError is a custom error class for identity-common-related errors.
 */
export class IdentityCommonError extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    this.name = 'IdentityCommonError'
  }
}
