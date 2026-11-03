/**
 * IdentityError is the base error class for all identity-common-ts packages.
 *
 * Package-specific error classes should extend this class.
 */
export class IdentityError extends Error {
  public details?: unknown

  constructor(message: string, details?: unknown) {
    super(message)
    Object.setPrototypeOf(this, IdentityError.prototype)
    this.name = 'IdentityError'
    this.details = details
  }

  getFullMessage(): string {
    return `${this.name}: ${this.message} ${this.details ? `- ${JSON.stringify(this.details)}` : ''}`
  }
}
