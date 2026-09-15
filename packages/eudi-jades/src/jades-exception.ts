/**
 * JAdES Exception
 *
 * Custom exception for JAdES-related errors.
 */

import { IdentityException } from '@owf/identity-common'

export class JAdESException extends IdentityException {
  constructor(message: string, details?: unknown) {
    super(message, details)
    this.name = 'JAdESException'
  }
}
