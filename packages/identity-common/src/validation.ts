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
  message: string
  /** Requirement identifier of the specification the validator implements, e.g. `GEN-6.6.1-05` */
  requirement?: string
  /** Details of the issue, of a type given by its code, e.g. the expected and the actual `typ` */
  context?: Context
}

/** The result of a validation */
export interface ValidationResult<Issue extends ValidationIssue = ValidationIssue> {
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
} as const

/** A code of {@link VALIDATION_CODES} */
export type CommonValidationCode = (typeof VALIDATION_CODES)[keyof typeof VALIDATION_CODES]

/** The context of the issues with a code of {@link VALIDATION_CODES} */
export interface ValidationIssueContexts {
  invalid_typ: { expected: string[]; actual: unknown }
  expired: { expiredAt: Date }
  not_yet_valid: { validFrom: Date }
  expires_before_issued: { issuedAt: Date; expiresAt: Date }
}

/** An issue with a code of {@link VALIDATION_CODES}, which always carries its context */
export type CommonValidationIssue<Code extends CommonValidationCode = CommonValidationCode> = {
  [C in Code]: ValidationIssue<C, ValidationIssueContexts[C]> & { context: ValidationIssueContexts[C] }
}[Code]

/**
 * The issues of a validator with the given codes: those of {@link VALIDATION_CODES} with
 * their context, and the others, so `issue.code === 'invalid_typ'` narrows the context.
 */
export type ValidationIssueOf<Code extends string> =
  | CommonValidationIssue<Extract<Code, CommonValidationCode>>
  | ValidationIssue<Exclude<Code, CommonValidationCode>>

/** The issue codes of zod, which schema validation issues keep unless they carry their own */
export type SchemaIssueCode =
  | 'invalid_type'
  | 'too_big'
  | 'too_small'
  | 'invalid_format'
  | 'not_multiple_of'
  | 'unrecognized_keys'
  | 'invalid_union'
  | 'invalid_key'
  | 'invalid_element'
  | 'invalid_value'
  | 'custom'

/**
 * What a custom schema issue carries in its `params` to become an issue with its own code,
 * e.g. with zod: `ctx.addIssue({ code: 'custom', message, params: { code: 'invalid_typ', context } })`
 */
export interface ValidationIssueParams<Code extends string = string, Context = unknown> {
  code: Code
  /** Defaults to `error` */
  severity?: ValidationSeverity
  requirement?: string
  context?: Context
}

/**
 * The structural part of a schema validation issue, as reported by zod and similar
 * schema libraries, so this package does not depend on one of them.
 */
export interface SchemaIssue {
  code: string
  path: readonly PropertyKey[]
  message: string
  /** The params of a custom issue, see {@link ValidationIssueParams} */
  params?: Record<string, unknown>
}

function issueParams(params: Record<string, unknown> | undefined): ValidationIssueParams | undefined {
  return typeof params?.code === 'string' ? (params as unknown as ValidationIssueParams) : undefined
}

/**
 * Convert a schema validation issue into a validation issue. A custom issue whose `params`
 * are {@link ValidationIssueParams} gets their code, severity, requirement and context.
 */
export function schemaIssueToValidationIssue(
  issue: SchemaIssue,
  severity: ValidationSeverity = 'error'
): ValidationIssue {
  const params = issueParams(issue.params)
  return {
    severity: params?.severity ?? severity,
    code: params?.code ?? issue.code,
    path: issue.path.map((key) => (typeof key === 'number' ? key : String(key))),
    message: issue.message,
    ...(params?.requirement ? { requirement: params.requirement } : {}),
    ...(params?.context !== undefined ? { context: params.context } : {}),
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

/** The issues with their path below the given one, e.g. `payload` for those of a JWT payload */
export function prefixIssuePaths<Issue extends ValidationIssue>(
  prefix: string | number,
  issues: readonly Issue[]
): Issue[] {
  return issues.map((issue) => ({ ...issue, path: [prefix, ...issue.path] }))
}
