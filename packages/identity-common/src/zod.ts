import z from 'zod'
import { createErrorMap, fromError } from 'zod-validation-error'
import { IdentityError } from './identity-error'

/**
 * The zod layer every package in this repository shares: one error map, one way of formatting a
 * `ZodError`, and one error class for a value that does not validate.
 *
 * It lives here rather than in each package so that a schema failure reads the same wherever it
 * happens, and so that `instanceof ValidationError` holds across packages.
 */

// biome-ignore lint/suspicious/noExplicitAny: intentionally unconstrained, used as a generic bound
export type BaseSchema = z.ZodType<any, any, any>

/**
 * The error map that makes a zod issue read as a sentence.
 *
 * Passed per parse rather than installed with `z.config`, which is global: these packages are
 * imported by applications that use zod themselves, and a library has no business changing what
 * every schema in the process reports when it fails. Pass it as `{ error: zodErrorMap }` wherever
 * zod is called directly rather than through the helpers here.
 */
export const zodErrorMap = createErrorMap()

const errorMap = zodErrorMap

export function formatZodError(error?: z.ZodError): string {
  if (!error) return ''

  return fromError(error, {
    prefix: '',
    prefixSeparator: '✖ ',
    issueSeparator: '\n✖ ',
    unionSeparator: '\n    OR ✖ ',
  }).toString()
}

/** What a failed parse reports: the formatted message, and the issues behind it. */
export interface ZodParseFailure {
  /** `errorMessage`, followed by the formatted issues. */
  message: string
  issues: z.ZodError['issues']
  error: z.ZodError
}

export type ZodParseResult<Schema extends BaseSchema> =
  | { success: true; data: z.infer<Schema> }
  | { success: false; failure: ZodParseFailure }

/**
 * Parses `data` against `schema`, reporting a failure as a formatted message and the issues behind
 * it rather than throwing.
 *
 * Packages build their own error on top of this — `@owf/jose` raises a `JoseValidationError`, for
 * instance — so that the class says which layer rejected the value while the message and the issues
 * are produced in one place.
 *
 * The data is never included in the message: these structures regularly carry values that should not
 * end up in a log.
 */
export function parseWithZod<Schema extends BaseSchema>(
  schema: Schema,
  data: unknown,
  errorMessage: string
): ZodParseResult<Schema> {
  const result = schema.safeParse(data, { error: errorMap })

  if (!result.success) {
    return {
      success: false,
      failure: {
        message: `${errorMessage}\n${formatZodError(result.error)}`,
        issues: result.error.issues,
        error: result.error,
      },
    }
  }

  return { success: true, data: result.data }
}

/**
 * A NumericDate: the number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC
 * date/time, ignoring leap seconds. Non-integer values are allowed.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7519#section-2
 */
export const zNumericDate = z.number()

/** A value does not validate against the schema it was parsed with. */
export class ValidationError extends IdentityError {
  public readonly zodError?: z.ZodError

  constructor(message: string, zodError?: z.ZodError) {
    super(zodError ? `${message}\n${formatZodError(zodError)}` : message, zodError?.issues)

    this.name = new.target.name

    // Not enumerable: a zod error serializes to a large structure, and this is the same data the
    // formatted message already carries.
    Object.defineProperty(this, 'zodError', {
      value: zodError,
      writable: false,
      enumerable: false,
    })
  }
}

/**
 * Parses `data` against `schema`, throwing a {@link ValidationError} when it does not match.
 */
export function parseWithErrorHandling<Schema extends BaseSchema>(
  schema: Schema,
  data: unknown,
  errorMessage = 'Error validating structure'
): z.infer<Schema> {
  const result = schema.safeParse(data, { error: errorMap })

  if (!result.success) {
    throw new ValidationError(errorMessage, result.error)
  }

  return result.data
}
