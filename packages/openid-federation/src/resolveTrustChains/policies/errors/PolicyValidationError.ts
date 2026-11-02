import { IdentityError } from '@owf/identity-common'
export type PolicyValidationErrorDetails = {
  path: string
  policyValue: unknown
  targetValue: unknown
}

export class PolicyValidationError extends IdentityError {
  public readonly details: PolicyValidationErrorDetails

  public constructor(message: string, details: PolicyValidationErrorDetails) {
    super(message)
    this.details = details
  }
}
