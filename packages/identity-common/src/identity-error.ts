import { getIdentityCommonConfig } from './config'

export interface IdentityErrorOptions {
  sensitive?: Record<string, unknown>
}

/**
 * IdentityError is the base error class for all identity-common-ts packages.
 *
 * Package-specific error classes should extend this class.
 */
export class IdentityError extends Error {
  public details?: unknown
  declare public readonly sensitive?: Record<string, unknown>

  constructor(message: string, details?: unknown, options?: IdentityErrorOptions) {
    super(
      options?.sensitive && getIdentityCommonConfig().includeSensitiveErrorDetails
        ? `${message} ${JSON.stringify(options.sensitive)}`
        : message
    )

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
    if (options?.sensitive) {
      Object.defineProperty(this, 'sensitive', { value: options.sensitive, enumerable: false })
    }
  }

  getFullMessage(): string {
    return `${this.name}: ${this.message} ${this.details ? `- ${JSON.stringify(this.details)}` : ''}`
  }
}

const ESCAPED_CONTROL_CHARACTERS: Record<string, string> = { '\n': '\\n', '\r': '\\r', '\t': '\\t' }

function isControlCharacter(code: number) {
  // C0 and C1 controls, DEL, and the line and paragraph separators
  return code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029
}

/**
 * A value as it can be put in an error message, which may be logged. Control characters are escaped, e.g. a line
 * break as `\n`, so a value of the input can't start a log line of its own, and a value longer than `maxLength`
 * characters is cut off.
 */
export function errorMessageValue(value: string | number, maxLength = 200): string {
  const text = String(value)
  const cut = text.length > maxLength ? `${text.slice(0, maxLength)}...` : text

  let escaped = ''
  for (const character of cut) {
    const code = character.charCodeAt(0)
    escaped += isControlCharacter(code)
      ? (ESCAPED_CONTROL_CHARACTERS[character] ?? `\\u${code.toString(16).padStart(4, '0')}`)
      : character
  }
  return escaped
}
