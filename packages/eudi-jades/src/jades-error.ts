/**
 * JAdES Error
 *
 * Custom error for JAdES-related failures.
 */

import { IdentityError, ValidationError } from '@owf/identity-common'
import type { JadesValidationIssue } from './validation'

export class JadesError extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    this.name = 'JadesError'
  }
}

/**
 * Thrown when a JAdES signature does not meet ETSI TS 119 182-1, with the `issues` of the validation. The message lists
 * the errors among them.
 */
export class JadesValidationError extends ValidationError<JadesValidationIssue> {}
