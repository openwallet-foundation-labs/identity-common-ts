import { IdentityException } from '@owf/identity-common'

/**
 * WRPRCException is a custom error class for WRPRC-related exceptions.
 */
export class WRPRCException extends IdentityException {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, WRPRCException.prototype)
    this.name = 'WRPRCException'
  }
}
