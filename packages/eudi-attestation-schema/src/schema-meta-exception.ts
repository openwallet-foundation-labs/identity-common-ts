import { IdentityException } from '@owf/identity-common'

export class SchemaMetaException extends IdentityException {
  constructor(message: string, details?: unknown) {
    super(message, details)
    this.name = 'SchemaMetaException'
  }
}
