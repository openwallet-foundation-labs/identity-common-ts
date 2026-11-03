import { IdentityError } from '@owf/identity-common'

/**
 * X509Error is thrown when a certificate or CRL cannot be parsed or created.
 */
export class X509Error extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, X509Error.prototype)
    this.name = 'X509Error'
  }
}
