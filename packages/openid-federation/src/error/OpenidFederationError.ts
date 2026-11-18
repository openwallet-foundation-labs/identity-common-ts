import { IdentityError } from '@owf/identity-common'
import type { ZodError } from 'zod'
import { PolicyErrorStage } from './PolicyErrorStage'

export class OpenidFederationError extends IdentityError {
  public constructor(
    public readonly errorCode: PolicyErrorStage,
    message?: string,
    public readonly cause?: unknown
  ) {
    super(message ?? '')
  }

  public static fromZodError(zodError: ZodError) {
    return new OpenidFederationError(PolicyErrorStage.Validation, undefined, zodError)
  }

  public static isMetadataPolicyCritError(error: unknown) {
    return error instanceof OpenidFederationError && error.errorCode === PolicyErrorStage.MetadataPolicyCrit
  }
}
