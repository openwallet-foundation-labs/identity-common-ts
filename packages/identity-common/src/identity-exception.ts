/**
 * IdentityException is the base error class for all identity-common-ts packages.
 *
 * Package-specific exception classes should extend this class.
 */
export class IdentityException extends Error {
  public details?: unknown

  constructor(message: string, details?: unknown) {
    super(message)

    // NOTE: `new.target` is the class that was constructed, so `instanceof` holds for every
    // subclass, however deep, without any of them having to repeat this. Setting
    // `IdentityException.prototype` here instead would overwrite the prototype that `super()`
    // installed, and break `instanceof` for every subclass that does not set it again itself.
    //
    // The call is only needed when this compiles down to ES5, where `super()` becomes
    // `Error.call(this)` and returns a new object rather than initializing `this`.
    Object.setPrototypeOf(this, new.target.prototype)
    this.name = 'IdentityException'
    this.details = details
  }

  getFullMessage(): string {
    return `${this.name}: ${this.message} ${this.details ? `- ${JSON.stringify(this.details)}` : ''}`
  }
}
