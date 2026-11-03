import { IdentityError, validationErrorMessage } from '@owf/identity-common'
import type { LoTEValidationIssue } from './validator'

/**
 * LoTEError is the error of LoTE operations.
 */
export class LoTEError extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, LoTEError.prototype)
    this.name = 'LoTEError'
  }
}

/**
 * Thrown when a LoTE document or one of its parts does not pass validation, with the `issues` of the validation. The message lists the errors among them.
 */
export class LoTEValidationError extends LoTEError {
  readonly issues: LoTEValidationIssue[]

  constructor(message: string, issues: LoTEValidationIssue[]) {
    super(validationErrorMessage(message, issues))
    Object.setPrototypeOf(this, LoTEValidationError.prototype)
    this.name = 'LoTEValidationError'
    this.issues = issues
  }
}
