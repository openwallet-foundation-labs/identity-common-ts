/**
 * IdentityError is the base error class for all identity-common-ts packages.
 *
 * Package-specific error classes should extend this class.
 */
export class IdentityError extends Error {
  public details?: unknown

  constructor(message: string, details?: unknown) {
    super(message)

    // NOTE: `new.target` is the class that was constructed, so `instanceof` holds for every
    // subclass, however deep, without any of them having to repeat this. Setting
    // `IdentityError.prototype` here instead would overwrite the prototype that `super()`
    // installed, and break `instanceof` for every subclass that does not set it again itself.
    //
    // The call is only needed when this compiles down to ES5, where `super()` becomes
    // `Error.call(this)` and returns a new object rather than initializing `this`.
    Object.setPrototypeOf(this, new.target.prototype)

    // Named after the class that was constructed for the same reason, so a subclass that does not
    // set a name is not reported as an `IdentityError`. One that does set it overrides this.
    this.name = new.target.name
    this.details = details
  }

  getFullMessage(): string {
    return `${this.name}: ${this.message} ${this.details ? `- ${JSON.stringify(this.details)}` : ''}`
  }
}
