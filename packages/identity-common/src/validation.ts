import { IdentityError } from './identity-error'

/**
 * A common shape for the outcome of a validation, so the validators of different packages
 * can be consumed the same way, for example to show which element of a parsed document
 * conforms and which does not.
 */

/**
 * `error` makes the validated value invalid, `warning` notes a deviation that does not,
 * and `info` is a note only
 */
export type ValidationSeverity = 'error' | 'warning' | 'info'

/** A single result of a validation */
export interface ValidationIssue<Code extends string = string, Context = unknown> {
  severity: ValidationSeverity
  /** Stable, machine readable code to branch on instead of the message */
  code: Code
  /**
   * Location of the checked element in the validated value, as property names and array
   * indices. Empty when the issue concerns the value as a whole.
   */
  path: (string | number)[]
  /**
   * `path` as a reader knows it, of the same length, e.g. `ExpirationTime (4)` where the path
   * has the CBOR key `4`. The message of a validation error uses it instead of `path`.
   */
  pathLabels?: (string | number)[]
  message: string
  /** Requirement identifier of the specification the validator implements, e.g. `GEN-6.6.1-05` */
  requirement?: string
  /** Details of the issue, of a type given by its code, e.g. the expected and the actual `typ` */
  context?: Context
}

/** The result of a validation */
export interface ValidationResult<Issue = ValidationIssue> {
  /** Whether none of the issues is an error */
  valid: boolean
  /** All issues, errors, warnings and infos, in the order they were found */
  issues: Issue[]
}

/**
 * Codes for checks that recur across specifications, so their issues look the same in
 * every package. Each comes with the context in {@link ValidationIssueContexts}.
 */
export const VALIDATION_CODES = {
  /** `typ` is missing or not one of the expected media types */
  INVALID_TYP: 'invalid_typ',
  /** The validity period has ended, e.g. `exp` or `notAfter` is in the past */
  EXPIRED: 'expired',
  /** The validity period has not started yet, e.g. `nbf` or `notBefore` is in the future */
  NOT_YET_VALID: 'not_yet_valid',
  /** The validity period ends at or before it starts, e.g. `exp` is at or before `iat` */
  EXPIRES_BEFORE_ISSUED: 'expires_before_issued',
  /** A claim the verifier requires is missing, e.g. `aud` when an audience is expected */
  CLAIM_MISSING: 'claim_missing',
  /** A claim is not one of the values the verifier expects, e.g. `aud` or `nonce` */
  CLAIM_VALUE_MISMATCH: 'claim_value_mismatch',
  /**
   * `crit` is invalid: in the unprotected header, or listing a registered header parameter or one
   * the header does not contain (RFC 7515 section 4.1.11)
   */
  INVALID_CRIT: 'invalid_crit',
  /** `crit` lists a header parameter the recipient does not understand (RFC 7515 section 4.1.11) */
  UNSUPPORTED_CRIT: 'unsupported_crit',
} as const

/** A code of {@link VALIDATION_CODES} */
export type CommonValidationCode = (typeof VALIDATION_CODES)[keyof typeof VALIDATION_CODES]

/**
 * Codes for the structural checks of a schema, the same in every package. Schema issues
 * only have these codes or one of the validator, never a code of the schema library.
 */
export const SCHEMA_VALIDATION_CODES = {
  /** A required value is missing, with the `expected` value as context, e.g. `string` */
  MISSING_VALUE: 'missing_value',
  /** A value is present that must not be */
  NOT_ALLOWED: 'not_allowed',
  /** A value has the wrong type, with the `expected` type as context, e.g. `string` or `int` */
  INVALID_TYPE: 'invalid_type',
  /** A value is not one of the allowed ones, with these as `allowed` when the schema lists them */
  INVALID_VALUE: 'invalid_value',
  /** A string does not have the required format, with the `format` as context, e.g. `url` */
  INVALID_FORMAT: 'invalid_format',
  /** A number, string length or array length is below the `minimum` */
  TOO_SMALL: 'too_small',
  /** A number, string length or array length is above the `maximum` */
  TOO_BIG: 'too_big',
  /** An object has members the schema does not allow, with their `keys` as context */
  UNRECOGNIZED_KEYS: 'unrecognized_keys',
} as const

/** A code of {@link SCHEMA_VALIDATION_CODES} */
export type SchemaValidationCode = (typeof SCHEMA_VALIDATION_CODES)[keyof typeof SCHEMA_VALIDATION_CODES]

/** The context of the issues with a code of {@link VALIDATION_CODES} or {@link SCHEMA_VALIDATION_CODES} */
export interface ValidationIssueContexts {
  invalid_typ: { expected: string[]; actual: unknown }
  expired: { expiredAt: Date }
  not_yet_valid: { validFrom: Date }
  expires_before_issued: { issuedAt: Date; expiresAt: Date }
  claim_value_mismatch: { expected: unknown[]; actual: unknown }
  /** The header parameter that `crit` lists, when the issue is about one */
  invalid_crit: { parameter?: string }
  unsupported_crit: { parameter: string; understood: string[] }
  missing_value: { expected: string }
  invalid_type: { expected: string }
  /** `branches` has the issues of each member of a union that none of them matches */
  invalid_value: { allowed?: unknown[]; branches?: ValidationIssue[][] }
  invalid_format: { format: string }
  /** `origin` is what is measured: `number`, `string` for its length, `array` for its items, ... */
  too_small: { minimum: number; inclusive: boolean; origin: string }
  too_big: { maximum: number; inclusive: boolean; origin: string }
  /** The keys as in the value, e.g. the numbers of a CBOR map */
  unrecognized_keys: { keys: (string | number)[] }
}

/** The fields of an issue besides its code and context */
type ValidationIssueFields = Omit<ValidationIssue, 'code' | 'context'>

/** The context of a code: the one of `Contexts`, else the one of {@link ValidationIssueContexts}, else none */
type ValidationContextOf<Code, Contexts> = Code extends keyof Contexts
  ? Contexts[Code]
  : Code extends keyof ValidationIssueContexts
    ? ValidationIssueContexts[Code]
    : undefined

/**
 * The code of an issue with the context of that code, which is required when the code has one
 * with a required member
 */
type CodeWithContext<Code extends string, Contexts> = {
  [C in Code]: { code: C } & (ValidationContextOf<C, Contexts> extends undefined
    ? { context?: undefined }
    : object extends ValidationContextOf<C, Contexts>
      ? { context?: ValidationContextOf<C, Contexts> }
      : { context: ValidationContextOf<C, Contexts> })
}[Code]

/**
 * The issues of a validator with the given codes, each with the context of its code. The
 * codes of {@link VALIDATION_CODES} have the context of {@link ValidationIssueContexts},
 * the ones in `Contexts` the context given there, and other codes none.
 *
 * The codes are a closed union, so checking the code narrows the context:
 * `if (issue.code === 'expired') issue.context.expiredAt`. A validator only creates issues
 * with its codes: {@link ValidationIssues} checks them, and `schemaIssueToValidationIssue`
 * only accepts a schema issue with one of them or of {@link SCHEMA_VALIDATION_CODES}.
 */
export type ValidationIssueOf<Code extends string, Contexts extends object = object> = ValidationIssueFields &
  CodeWithContext<Code, Contexts>

/**
 * An issue to add, as {@link ValidationIssueOf}, but an error unless `severity` says
 * otherwise and with an empty `path` unless given
 */
export type ValidationIssueInput<Code extends string, Contexts extends object = object> = Omit<
  ValidationIssueFields,
  'severity' | 'path'
> &
  Partial<Pick<ValidationIssueFields, 'severity' | 'path'>> &
  CodeWithContext<Code, Contexts>

/**
 * Collects the issues of a validation with the given codes, each with the context of its
 * code, e.g. for checks that are not part of a schema.
 *
 * @example
 * ```typescript
 * const issues = new ValidationIssues<'expired' | 'missing_name'>()
 * issues.add({ code: 'expired', path: ['exp'], message: 'Expired', context: { expiredAt } })
 * return issues.result()
 * ```
 */
export class ValidationIssues<Code extends string, Contexts extends object = object> {
  readonly issues: ValidationIssueOf<Code, Contexts>[] = []

  add(issue: ValidationIssueInput<Code, Contexts>): void {
    this.issues.push({
      ...issue,
      severity: issue.severity ?? 'error',
      path: issue.path ?? [],
    } as ValidationIssueOf<Code, Contexts>)
  }

  result(): ValidationResult<ValidationIssueOf<Code, Contexts>> {
    return { valid: !this.issues.some((issue) => issue.severity === 'error'), issues: this.issues }
  }
}

/** Whether any of the issues is an error */
export function hasValidationErrors(issues: readonly ValidationIssue[]): boolean {
  return issues.some((issue) => issue.severity === 'error')
}

/** The errors among the issues of a result, e.g. to report when it is not valid */
export function validationErrors<Issue extends ValidationIssue>(result: ValidationResult<Issue>): Issue[] {
  return result.issues.filter((issue) => issue.severity === 'error')
}

/** The result of a validation with the given issues, valid when none of them is an error */
export function toValidationResult<Issue extends ValidationIssue>(issues: Issue[]): ValidationResult<Issue> {
  return { valid: !hasValidationErrors(issues), issues }
}

/**
 * The message of an error thrown for a failed validation: the given message, followed by
 * the errors among the issues with their path and code, each on an indented line of its own
 */
export function validationErrorMessage(message: string, issues: readonly ValidationIssue[]): string {
  const errors = issues.filter((issue) => issue.severity === 'error')
  const lines = errors.map((issue) => {
    const path = issue.pathLabels ?? issue.path
    return `${path.length ? `${path.join('.')}: ` : ''}${issue.message} (${issue.code})`
  })
  return lines.length ? `${message}\n${lines.map((line) => `  - ${line}`).join('\n')}` : message
}

/** The issues with their path below the given one, e.g. `payload` for those of a JWT payload */
export function prefixIssuePaths<Issue extends ValidationIssue>(
  prefix: string | number,
  issues: readonly Issue[]
): Issue[] {
  return issues.map((issue) => ({
    ...issue,
    path: [prefix, ...issue.path],
    ...(issue.pathLabels ? { pathLabels: [prefix, ...issue.pathLabels] } : {}),
  }))
}

/**
 * Thrown when a value does not validate, with the `issues` of the validation. The message
 * lists the errors among them, see {@link validationErrorMessage}.
 */
export class ValidationError<Issue extends ValidationIssue = ValidationIssue> extends IdentityError {
  readonly issues: Issue[]

  constructor(message: string, issues: Issue[]) {
    super(validationErrorMessage(message, issues))
    this.issues = issues
  }

  /**
   * The first issue with `code`, typed by its code, or `undefined` when there is none
   *
   * @example
   * ```typescript
   * const expired = error.findIssue('expired')
   * if (expired) console.log(expired.context.expiredAt)
   * ```
   */
  findIssue<Code extends Issue['code']>(code: Code): (Issue & { code: Code }) | undefined {
    return this.issues.find((issue): issue is Issue & { code: Code } => issue.code === code)
  }
}
