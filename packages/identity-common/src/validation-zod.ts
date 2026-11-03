import { z } from 'zod'
import { isJwtTyp } from './content-type'
import { IdentityCommonError } from './identity-common-error'
import {
  type CommonValidationCode,
  SCHEMA_VALIDATION_CODES,
  type SchemaValidationCode,
  VALIDATION_CODES,
  ValidationError,
  type ValidationIssue,
  type ValidationIssueInput,
  type ValidationIssueOf,
  type ValidationSeverity,
} from './validation'

// biome-ignore lint/suspicious/noExplicitAny: intentionally unconstrained, used as a generic bound
export type BaseSchema = z.ZodType<any, any, any>

/** A JWT NumericDate, see RFC 7519 section 2 */
export const zNumericDate = z.number({
  error: 'expected a NumericDate, the number of seconds since 1970-01-01T00:00:00Z',
})

/**
 * A string that is not empty. Use it for a string unless the specification allows it to be empty.
 */
export const zNonEmptyString = z.string().min(1, { message: 'Expected a non-empty string' })

/**
 * A base64url encoded value without padding, as used everywhere in JOSE.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-2
 */
export const zBase64Url = z.base64url({ message: 'Expected an unpadded base64url encoded string' })

/** What `addValidationIssue` puts in the `params` of a custom zod issue */
interface ValidationIssueParams {
  code: string
  severity?: ValidationSeverity
  requirement?: string
  context?: unknown
}

/**
 * Add an issue with one of our codes in a zod refinement, e.g. in `superRefine`. zod gets
 * it as a custom issue at the path of the refined value, below `path` if given, and
 * `parseWithSchema` turns it back into the issue with its code and context.
 *
 * @example
 * ```typescript
 * addValidationIssue(ctx, { code: 'too_small', message, context: { minimum: 1, inclusive: true, origin: 'string' } })
 * // A code of the package, with its contexts if any
 * addValidationIssue<RegistrationCertificateValidationCode>(ctx, { code: 'missing_entitlement', path: ['entitlements'], message })
 * ```
 */
export function addValidationIssue<
  Code extends string = CommonValidationCode | SchemaValidationCode,
  Contexts extends object = object,
>(
  ctx: Pick<z.RefinementCtx, 'addIssue'>,
  { message, path, pathLabels, ...params }: ValidationIssueInput<Code, Contexts>
): void {
  ctx.addIssue({
    code: 'custom',
    message,
    params,
    ...(path ? { path } : {}),
    ...(pathLabels ? { pathLabels } : {}),
  } as Parameters<typeof ctx.addIssue>[0])
}

const ZOD_MESSAGE_PREFIX = /^(Invalid (input|number|option|string)|Too (big|small)): /
const zodLocaleError = z.locales.en().localeError

/**
 * The English messages of zod without their prefix, e.g. `Invalid input: `, as the code of the
 * issue says it, and with `expected to not be defined` for a value that must be absent. Pass it per
 * parse as `error`. A message the schema sets wins over it.
 */
export const zodErrorMap: z.core.$ZodErrorMap = (issue) => {
  const message = zodLocaleError(issue)
  const text = (typeof message === 'string' ? message : message?.message)?.replace(ZOD_MESSAGE_PREFIX, '')
  // `never` and `undefined` mean the value must be absent, which is the `not_allowed` code
  return issue.code === 'invalid_type' && (issue.expected === 'never' || issue.expected === 'undefined')
    ? text?.replace(/^expected (never|undefined)\b/, 'expected to not be defined')
    : text
}

/** What zod expected instead of an absent value, e.g. `string`, when it says so */
function expectedOf(issue: z.core.$ZodIssue): string | undefined {
  switch (issue.code) {
    case 'invalid_type':
      return issue.expected
    case 'invalid_value':
      return issue.values.map((value) => (typeof value === 'string' ? `"${value}"` : String(value))).join(' or ')
    case 'invalid_union': {
      const expected = issue.errors.map((branch) => (branch.length === 1 ? expectedOf(branch[0]) : undefined))
      return expected.length && expected.every(Boolean) ? expected.join(' or ') : undefined
    }
    default:
      return undefined
  }
}

/** The code and context of an issue zod reports itself, see {@link SCHEMA_VALIDATION_CODES} */
function schemaCode(issue: z.core.$ZodIssue): { code: SchemaValidationCode; context?: unknown } | undefined {
  const C = SCHEMA_VALIDATION_CODES
  // With `reportInput`, an issue for an absent value has `input` undefined
  const expected = 'input' in issue && issue.input === undefined ? expectedOf(issue) : undefined
  if (expected) return { code: C.MISSING_VALUE, context: { expected } }
  switch (issue.code) {
    case 'invalid_type':
      return issue.expected === 'undefined' || issue.expected === 'never'
        ? { code: C.NOT_ALLOWED }
        : { code: C.INVALID_TYPE, context: { expected: issue.expected } }
    case 'invalid_value':
      return { code: C.INVALID_VALUE, context: { allowed: issue.values } }
    case 'invalid_union':
      // A discriminated union whose discriminator matches none of the options lists them
      return { code: C.INVALID_VALUE, context: 'options' in issue && issue.options ? { allowed: issue.options } : {} }
    case 'invalid_key':
    case 'invalid_element':
    case 'not_multiple_of':
      return { code: C.INVALID_VALUE, context: {} }
    case 'invalid_format':
      return { code: C.INVALID_FORMAT, context: { format: issue.format } }
    case 'too_small':
      return {
        code: C.TOO_SMALL,
        context: { minimum: Number(issue.minimum), inclusive: issue.inclusive ?? true, origin: issue.origin },
      }
    case 'too_big':
      return {
        code: C.TOO_BIG,
        context: { maximum: Number(issue.maximum), inclusive: issue.inclusive ?? true, origin: issue.origin },
      }
    case 'unrecognized_keys':
      return { code: C.UNRECOGNIZED_KEYS, context: { keys: issue.keys } }
    case 'custom':
      return undefined
    default: {
      // A type error when zod adds an issue code, so it gets a mapping
      const unknown: never = issue
      throw new IdentityCommonError(`Unknown zod issue code '${(unknown as { code: string }).code}'`)
    }
  }
}

/**
 * Convert a zod issue into an issue of a validator with the given codes. An issue zod
 * reports itself gets a code of {@link SCHEMA_VALIDATION_CODES}. A custom issue added with
 * `addValidationIssue` gets its code, severity, requirement and context.
 *
 * Parse with `reportInput`, as `parseWithSchema` does, to tell a `missing_value` from an
 * `invalid_type`. A `pathLabels` on the zod issue, as the typed map of `@owf/cose` adds, labels
 * the end of its path.
 *
 * Without `codes`, for a schema that is not one of a validator, e.g. one a caller passes in,
 * the codes of {@link VALIDATION_CODES} are allowed, and any other custom issue gets
 * `invalid_value`.
 *
 * @throws IdentityCommonError when `codes` are given, for a custom issue without a code, or
 * with a code that is neither one of `codes` nor of {@link SCHEMA_VALIDATION_CODES}: the
 * schema has a check that the validator does not list.
 */
export function schemaIssueToValidationIssue<
  Code extends string = CommonValidationCode,
  Contexts extends object = object,
>(
  issue: z.core.$ZodIssue,
  { codes }: { codes?: Readonly<Record<string, Code>> } = {}
): ValidationIssueOf<Code | SchemaValidationCode, Contexts> {
  const path = issue.path.map((key) => (typeof key === 'number' ? key : String(key)))
  // The schemas around the one that labelled the path only put their keys in front of it
  const labels = (issue as { pathLabels?: (string | number)[] }).pathLabels
  const pathLabels = labels && [...path.slice(0, path.length - labels.length), ...labels]
  const fields = { severity: 'error', path, ...(pathLabels ? { pathLabels } : {}), message: issue.message }
  const schema = schemaCode(issue)
  if (schema) {
    const union = issue.code === 'invalid_union' && schema.code === SCHEMA_VALIDATION_CODES.INVALID_VALUE
    return { ...fields, ...schema, ...(union ? unionFields(issue, { codes }) : {}) } as unknown as ValidationIssueOf<
      Code | SchemaValidationCode,
      Contexts
    >
  }

  const params = (issue as z.core.$ZodIssueCustom).params as Partial<ValidationIssueParams> | undefined
  const allowed: string[] = [
    ...Object.values<string>(codes ?? VALIDATION_CODES),
    ...Object.values(SCHEMA_VALIDATION_CODES),
  ]
  if (typeof params?.code !== 'string' || !allowed.includes(params.code)) {
    if (!codes) {
      return { ...fields, code: SCHEMA_VALIDATION_CODES.INVALID_VALUE, context: {} } as unknown as ValidationIssueOf<
        Code | SchemaValidationCode,
        Contexts
      >
    }
    throw new IdentityCommonError(
      `The schema issue at '${path.join('.')}' has ${params?.code ? `the code '${params.code}', which is not a code of the validator` : 'no validation code'}: ${issue.message}`
    )
  }
  return {
    ...fields,
    severity: params.severity ?? 'error',
    code: params.code,
    ...(params.requirement ? { requirement: params.requirement } : {}),
    ...(params.context !== undefined ? { context: params.context } : {}),
  } as unknown as ValidationIssueOf<Code | SchemaValidationCode, Contexts>
}

/**
 * The issues of each member of a union that none of them matches, at their path in the parsed
 * value, and a message with the expected types when no member got further than its type
 */
function unionFields(
  issue: z.core.$ZodIssueInvalidUnion,
  options: { codes?: Readonly<Record<string, string>> }
): { message?: string; context?: { branches: ValidationIssue[][]; labels?: string[] } } {
  if (!issue.errors.length) return {}
  const branches = issue.errors.map((branch) =>
    branch.map((member) => schemaIssueToValidationIssue({ ...member, path: [...issue.path, ...member.path] }, options))
  )
  const types = branches.map((branch) =>
    branch.length === 1 &&
    branch[0].code === SCHEMA_VALIDATION_CODES.INVALID_TYPE &&
    branch[0].path.length === issue.path.length
      ? (branch[0].context as unknown as { expected: string }).expected
      : undefined
  )
  const labels = (issue as { [UNION_LABELS]?: string[] })[UNION_LABELS]
  return {
    // Only zod's generic message is replaced, not one the schema sets
    ...(types.every(Boolean) && issue.message === 'Invalid input' ? { message: `expected ${types.join(' or ')}` } : {}),
    context: { branches, ...(labels ? { labels: [...labels] } : {}) },
  }
}

/** The key under which {@link unionParams} puts the labels of the members on the issue of a union */
const UNION_LABELS = 'unionLabels'

/**
 * The params of a union whose members have a label, e.g. the version of a specification each one
 * implements. The issue of a value that no member matches has `message`, and the message of a
 * validation error names each member by its label.
 *
 * @example
 * ```typescript
 * z.union([zMetadataV1, zMetadataDraft11], unionParams('Invalid metadata', ['version 1.0', 'draft 11']))
 * ```
 */
export function unionParams(message: string, labels?: readonly string[]) {
  return {
    error: (issue: z.core.$ZodRawIssue) => {
      // zod copies the own properties of the issue into the one it reports, so the labels reach the conversion
      if (labels && issue.code === 'invalid_union') Object.assign(issue, { [UNION_LABELS]: labels })
      return message
    },
  }
}

/** The result of {@link parseWithSchema}: the parsed value, or the issues of the value that does not validate */
export type SchemaParseResult<Output, Issue = ValidationIssueOf<CommonValidationCode | SchemaValidationCode>> =
  | { success: true; data: Output }
  | { success: false; issues: Issue[] }

/**
 * Parse a value with a zod schema, with the issues as validation issues of a validator with
 * the given codes, see {@link schemaIssueToValidationIssue}
 */
export function parseWithSchema<
  Schema extends z.ZodType,
  Code extends string = CommonValidationCode,
  Contexts extends object = object,
>(
  schema: Schema,
  value: unknown,
  options: { codes?: Readonly<Record<string, Code>> } = {}
): SchemaParseResult<z.output<Schema>, ValidationIssueOf<Code | SchemaValidationCode, Contexts>> {
  const result = schema.safeParse(value, { reportInput: true, error: zodErrorMap })
  if (result.success) return { success: true, data: result.data }
  return {
    success: false,
    issues: result.error.issues.map((issue) => schemaIssueToValidationIssue<Code, Contexts>(issue, options)),
  }
}

/**
 * Parse a value with a zod schema, throwing a {@link ValidationError} with its issues, see
 * {@link schemaIssueToValidationIssue}, when it does not validate. Pass `ErrorClass` to throw
 * the validation error of a package, e.g. `JoseValidationError`. The value is not part of the
 * message, as it may be confidential.
 */
export function parseWithErrorHandling<Schema extends z.ZodType>(
  schema: Schema,
  value: unknown,
  message = 'Error validating structure',
  ErrorClass: new (
    message: string,
    issues: ValidationIssueOf<CommonValidationCode | SchemaValidationCode>[]
  ) => ValidationError = ValidationError
): z.output<Schema> {
  const result = parseWithSchema(schema, value)
  if (!result.success) throw new ErrorClass(message, result.issues)
  return result.data
}

/**
 * A `typ` header that is one of the expected media types, compared with {@link isJwtTyp} and kept as
 * received. Any other value gives an `invalid_typ` issue with the expected and the actual value as context.
 * The input is typed as the expected values, the output as a `string`, as it may be in another casing or
 * have the `application/` prefix: compare it with {@link isJwtTyp}.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8725#section-3.11
 */
export function zTyp<const Typ extends string>(...expected: [Typ, ...Typ[]]) {
  return z
    .custom<Typ>()
    .superRefine((typ, ctx) => {
      if (expected.some((type) => isJwtTyp(typ, type))) return
      const expectedText = expected.join(' or ')
      addValidationIssue(ctx, {
        code: VALIDATION_CODES.INVALID_TYP,
        message: typ === undefined ? `typ is missing, it must be ${expectedText}` : `typ must be ${expectedText}`,
        context: { expected, actual: typ },
      })
    })
    .transform((typ): string => typ)
}
