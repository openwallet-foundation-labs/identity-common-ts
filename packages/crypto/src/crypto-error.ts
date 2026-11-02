import { IdentityError } from '@owf/identity-common'

/**
 * CryptoError is a custom error class for crypto-related errors.
 */
export class CryptoError extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, CryptoError.prototype)
    this.name = 'CryptoError'
  }
}
