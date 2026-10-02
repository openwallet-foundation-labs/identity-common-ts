import { IdentityException } from '@owf/identity-common'

/**
 * AccessCertificateException is thrown when an access certificate cannot be
 * parsed, fails validation in an assert helper, or cannot be created.
 */
export class AccessCertificateException extends IdentityException {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, AccessCertificateException.prototype)
    this.name = 'AccessCertificateException'
  }
}
