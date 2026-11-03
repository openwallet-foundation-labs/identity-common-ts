import { IdentityError, validationErrorMessage } from '@owf/identity-common'
import type { AccessCertificateValidationIssue } from './validate'

/**
 * AccessCertificateError is thrown when an access certificate cannot be parsed or created.
 */
export class AccessCertificateError extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, AccessCertificateError.prototype)
    this.name = 'AccessCertificateError'
  }
}

/**
 * Thrown when an access certificate does not pass validation in an assert or create function, with the `issues` of the validation. The message lists the errors among them.
 */
export class AccessCertificateValidationError extends AccessCertificateError {
  readonly issues: AccessCertificateValidationIssue[]

  constructor(message: string, issues: AccessCertificateValidationIssue[]) {
    super(validationErrorMessage(message, issues))
    Object.setPrototypeOf(this, AccessCertificateValidationError.prototype)
    this.name = 'AccessCertificateValidationError'
    this.issues = issues
  }
}
