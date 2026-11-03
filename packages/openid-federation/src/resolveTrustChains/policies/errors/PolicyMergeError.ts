import { IdentityError } from '@owf/identity-common'
import type { MetadataPolicyOperator } from '../../../metadata'

export type PolicyOperatorMergeErrorDetails = {
  path: string
  operatorA: MetadataPolicyOperator
  operatorB: MetadataPolicyOperator
}

export class PolicyOperatorMergeError extends IdentityError {
  public readonly details: PolicyOperatorMergeErrorDetails

  constructor(message: string, details: PolicyOperatorMergeErrorDetails) {
    super(message)
    this.details = details
  }
}
