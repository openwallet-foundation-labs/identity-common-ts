import { IdentityError } from '@owf/identity-common'

export class SchemaMetaError extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    this.name = 'SchemaMetaError'
  }
}
