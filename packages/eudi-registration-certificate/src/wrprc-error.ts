import { IdentityError, validationErrorMessage } from '@owf/identity-common'
import type { WRPRCValidationIssue } from './validator'

/**
 * WRPRCError is the error of WRPRC operations.
 */
export class WRPRCError extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, WRPRCError.prototype)
    this.name = 'WRPRCError'
  }
}

/**
 * Thrown when a WRPRC does not pass validation, with the `issues` of the validation. The message lists the errors among them.
 */
export class WRPRCValidationError extends WRPRCError {
  readonly issues: WRPRCValidationIssue[]

  constructor(message: string, issues: WRPRCValidationIssue[]) {
    super(validationErrorMessage(message, issues))
    Object.setPrototypeOf(this, WRPRCValidationError.prototype)
    this.name = 'WRPRCValidationError'
    this.issues = issues
  }
}
