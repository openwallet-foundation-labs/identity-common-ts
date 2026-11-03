import { z } from 'zod'
import { IdentityCommonError } from './identity-common-error'
import {
  type CommonValidationCode,
  SCHEMA_VALIDATION_CODES,
  type SchemaValidationCode,
  VALIDATION_CODES,
  type ValidationIssueInput,
  type ValidationIssueOf,
  type ValidationSeverity,
} from './validation'

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
>(ctx: Pick<z.RefinementCtx, 'addIssue'>, { message, path, ...params }: ValidationIssueInput<Code, Contexts>): void {
  ctx.addIssue({ code: 'custom', message, params, ...(path ? { path } : {}) })
}

/** The code and context of an issue zod reports itself, see {@link SCHEMA_VALIDATION_CODES} */
function schemaCode(issue: z.core.$ZodIssue): { code: SchemaValidationCode; context?: unknown } | undefined {
  const C = SCHEMA_VALIDATION_CODES
  // With `reportInput`, an issue for an absent value has `input` undefined
  if ('input' in issue && issue.input === undefined && issue.code !== 'custom') return { code: C.MISSING }
  switch (issue.code) {
    case 'invalid_type':
      return issue.expected === 'undefined' || issue.expected === 'never'
        ? { code: C.NOT_ALLOWED }
        : { code: C.INVALID_TYPE, context: { expected: issue.expected } }
    case 'invalid_value':
      return { code: C.INVALID_VALUE, context: { allowed: issue.values } }
    case 'invalid_union':
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
 * Parse with `reportInput`, as `parseWithSchema` does, to tell a `missing` value from one
 * of an `invalid_type`.
 *
 * @throws IdentityCommonError for a custom issue without a code, or with a code that is
 * neither one of `codes` nor of {@link SCHEMA_VALIDATION_CODES}: the schema has a check
 * that the validator does not list.
 */
export function schemaIssueToValidationIssue<Code extends string = never, Contexts extends object = object>(
  issue: z.core.$ZodIssue,
  { codes = {} }: { codes?: Readonly<Record<string, Code>> } = {}
): ValidationIssueOf<Code | SchemaValidationCode, Contexts> {
  const path = issue.path.map((key) => (typeof key === 'number' ? key : String(key)))
  const fields = { severity: 'error', path, message: issue.message }
  const schema = schemaCode(issue)
  if (schema) return { ...fields, ...schema } as unknown as ValidationIssueOf<Code | SchemaValidationCode, Contexts>

  const params = (issue as z.core.$ZodIssueCustom).params as Partial<ValidationIssueParams> | undefined
  const allowed: string[] = [...Object.values<string>(codes), ...Object.values(SCHEMA_VALIDATION_CODES)]
  if (typeof params?.code !== 'string' || !allowed.includes(params.code)) {
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
 * Parse a value with a zod schema, with the issues as validation issues of a validator with
 * the given codes, see {@link schemaIssueToValidationIssue}
 */
export function parseWithSchema<
  Schema extends z.ZodType,
  Code extends string = never,
  Contexts extends object = object,
>(
  schema: Schema,
  value: unknown,
  options: { codes?: Readonly<Record<string, Code>> } = {}
):
  | { success: true; data: z.output<Schema> }
  | { success: false; issues: ValidationIssueOf<Code | SchemaValidationCode, Contexts>[] } {
  const result = schema.safeParse(value, { reportInput: true })
  if (result.success) return { success: true, data: result.data }
  return {
    success: false,
    issues: result.error.issues.map((issue) => schemaIssueToValidationIssue<Code, Contexts>(issue, options)),
  }
}

/**
 * A `typ` header that is one of the expected media types. Any other value gives an
 * `invalid_typ` issue with the expected and the actual value as context.
 */
export function zTyp<const Typ extends string>(...expected: [Typ, ...Typ[]]) {
  return z.custom<Typ>().superRefine((typ, ctx) => {
    if (expected.includes(typ)) return
    const expectedText = expected.join(' or ')
    addValidationIssue(ctx, {
      code: VALIDATION_CODES.INVALID_TYP,
      message: typ === undefined ? `typ is missing, it must be ${expectedText}` : `typ must be ${expectedText}`,
      context: { expected, actual: typ },
    })
  })
}
