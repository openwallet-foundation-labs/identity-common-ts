import { IdentityException } from '@owf/identity-common'

/**
 * X509Exception is thrown when a certificate or CRL cannot be parsed or created.
 */
export class X509Exception extends IdentityException {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, X509Exception.prototype)
    this.name = 'X509Exception'
  }
}
