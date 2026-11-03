import { IdentityError, validationErrorMessage } from '@owf/identity-common'
import type { LoteValidationIssue } from './validator'

/**
 * LoteError is the error of LoTE operations.
 */
export class LoteError extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, LoteError.prototype)
    this.name = 'LoteError'
  }
}

/**
 * Thrown when a LoTE document or one of its parts does not pass validation, with the `issues` of the validation. The message lists the errors among them.
 */
export class LoteValidationError extends LoteError {
  readonly issues: LoteValidationIssue[]

  constructor(message: string, issues: LoteValidationIssue[]) {
    super(validationErrorMessage(message, issues))
    Object.setPrototypeOf(this, LoteValidationError.prototype)
    this.name = 'LoteValidationError'
    this.issues = issues
  }
}
