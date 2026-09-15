import { IdentityException } from './identity-exception'

/**
 * IdentityCommonException is a custom error class for identity-common-related exceptions.
 */
export class IdentityCommonException extends IdentityException {
  constructor(message: string, details?: unknown) {
    super(message, details)
    this.name = 'IdentityCommonException'
  }
}
