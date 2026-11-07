import { ValidationError } from '@owf/identity-common'
import type { RegistrationCertificateValidationIssue } from './validator'

/**
 * Thrown when a registration certificate does not pass validation, with the `issues` of the validation. The message lists the errors among them.
 */
export class RegistrationCertificateValidationError extends ValidationError<RegistrationCertificateValidationIssue> {}
