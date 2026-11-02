import { IdentityError, validationErrorMessage } from '@owf/identity-common'
import type { RegistrationCertificateValidationIssue } from './validator'

/**
 * RegistrationCertificateError is the error of registration certificate operations.
 */
export class RegistrationCertificateError extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, RegistrationCertificateError.prototype)
    this.name = 'RegistrationCertificateError'
  }
}

/**
 * Thrown when a registration certificate does not pass validation, with the `issues` of the validation. The message lists the errors among them.
 */
export class RegistrationCertificateValidationError extends RegistrationCertificateError {
  readonly issues: RegistrationCertificateValidationIssue[]

  constructor(message: string, issues: RegistrationCertificateValidationIssue[]) {
    super(validationErrorMessage(message, issues))
    Object.setPrototypeOf(this, RegistrationCertificateValidationError.prototype)
    this.name = 'RegistrationCertificateValidationError'
    this.issues = issues
  }
}
