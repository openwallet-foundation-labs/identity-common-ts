import {
  addValidationIssue,
  parseWithSchema,
  type SchemaValidationCode,
  type ValidationIssueInput,
  type ValidationIssueOf,
  validationErrorMessage,
} from '@owf/identity-common'
import { z } from 'zod'
import { DcqlParseError } from './dcql-error/e-dcql.js'

export const idRegex = /^[a-zA-Z0-9_-]+$/

export const DcqlNotDisclosed = Symbol.for('dcql.not_disclosed')
export type DcqlNotDisclosed = typeof DcqlNotDisclosed

export function asNonEmptyArrayOrUndefined<U>(array: U[]): NonEmptyArray<U> | undefined {
  return array.length > 0 ? (array as NonEmptyArray<U>) : undefined
}

export function isNonEmptyArray<U>(array: U[]): array is NonEmptyArray<U> {
  return array.length > 0
}

export type NonEmptyArray<T> = [T, ...T[]]
export type ToNonEmptyArray<T extends Array<unknown>> = [T[number], ...T]

// The cast keeps the non-empty tuple type, which a length check does not narrow to in zod 4
export const zNonEmptyArray = <Item extends z.ZodType>(item: Item) =>
  z
    .array(item, { error: (issue) => `Expected input to be an array, but received '${typeof issue.input}'` })
    .superRefine((array, ctx) => {
      if (array.length > 0) return
      addDcqlIssue(ctx, {
        code: DCQL_VALIDATION_CODES.EMPTY_ARRAY,
        message: 'Array must be non-empty and have length of at least 1',
      })
    }) as unknown as z.ZodType<NonEmptyArray<z.output<Item>>, z.input<Item>[]>

export const zIdString = z
  .string()
  .regex(idRegex, 'Expected a non-empty string of alphanumeric, underscore (_) or hyphen (-) characters')
export const base64urlRegex = /^(?:[\w-]{4})*(?:[\w-]{2}(?:==)?|[\w-]{3}=?)?$/iu

export const zJsonRecord = z.record(z.string(), z.json())

/**
 * Codes of the issues of a DCQL query that breaks a rule of OpenID4VP beyond its structure, and of a
 * credential or presentation that does not match a query
 */
export const DCQL_VALIDATION_CODES = {
  /** A credential query `id` is present more than once (OpenID4VP 1.0 Section 6.1) */
  DUPLICATE_CREDENTIAL_QUERY_ID: 'duplicate_credential_query_id',
  /** A credential set option refers to a credential query `id` that is not in `credentials` (OpenID4VP 1.0 Section 6.2) */
  UNKNOWN_CREDENTIAL_QUERY_ID: 'unknown_credential_query_id',
  /** A claim `id` is present more than once in the `claims` of a credential query (OpenID4VP 1.0 Section 6.3) */
  DUPLICATE_CLAIM_ID: 'duplicate_claim_id',
  /** A claim set refers to a claim `id` that is not in the `claims` of the credential query (OpenID4VP 1.0 Section 6.1) */
  UNKNOWN_CLAIM_ID: 'unknown_claim_id',
  /** An array that must not be empty is, e.g. `claims` */
  EMPTY_ARRAY: 'empty_array',
  /** The claims path pointer does not point to a value in the credential */
  CLAIMS_PATH_NOT_FOUND: 'claims_path_not_found',
  /** The claim is not one of the `values` of the claims query */
  CLAIM_VALUES_MISMATCH: 'claim_values_mismatch',
  /** The credential format is not the `format` of the credential query */
  CREDENTIAL_FORMAT_MISMATCH: 'credential_format_mismatch',
  /** The doctype is not the `doctype_value` of the credential query */
  DOCTYPE_MISMATCH: 'doctype_mismatch',
  /** The vct is not one of the `vct_values` of the credential query */
  VCT_MISMATCH: 'vct_mismatch',
  /** The type does not include all of one of the `type_values` of the credential query */
  TYPE_MISMATCH: 'type_mismatch',
  /** The credential query requires cryptographic holder binding, and the credential has none */
  CRYPTOGRAPHIC_HOLDER_BINDING_REQUIRED: 'cryptographic_holder_binding_required',
  /** The authority of the credential does not match the trusted authorities query */
  TRUSTED_AUTHORITY_MISMATCH: 'trusted_authority_mismatch',
} as const

/** A code of {@link DCQL_VALIDATION_CODES} */
export type DcqlValidationCode = (typeof DCQL_VALIDATION_CODES)[keyof typeof DCQL_VALIDATION_CODES]

/** The context of the issues with a code of {@link DCQL_VALIDATION_CODES}, the codes not listed have none */
export interface DcqlValidationContexts {
  claim_values_mismatch: { expected: (string | number | boolean)[]; actual: unknown }
  credential_format_mismatch: { expected: string; actual: unknown }
  doctype_mismatch: { expected: string; actual: unknown }
  vct_mismatch: { expected: string[]; actual: unknown }
  type_mismatch: { expected: string[][]; actual: unknown }
  trusted_authority_mismatch: { expected: { type: string; values: string[] }; actual: unknown }
}

/**
 * An issue of a DCQL parse or match: a {@link DcqlValidationCode} when a query breaks a rule or a
 * credential does not match it, else a schema code when the input does not have the structure of the schema
 */
export type DcqlValidationIssue = ValidationIssueOf<DcqlValidationCode | SchemaValidationCode, DcqlValidationContexts>

/** The issues of a failed match or parse */
export const zIssues = z.array(z.custom<DcqlValidationIssue>())

/** Add an issue with a DCQL or a schema code in a zod refinement */
export const addDcqlIssue = (
  ctx: Pick<z.RefinementCtx, 'addIssue'>,
  issue: ValidationIssueInput<DcqlValidationCode | SchemaValidationCode, DcqlValidationContexts>
) => addValidationIssue<DcqlValidationCode | SchemaValidationCode, DcqlValidationContexts>(ctx, issue)

/** Parse with the schema, with its issues as {@link DcqlValidationIssue}s */
export const parseDcql = <Schema extends z.ZodType>(schema: Schema, value: unknown) =>
  parseWithSchema<Schema, DcqlValidationCode, DcqlValidationContexts>(schema, value, { codes: DCQL_VALIDATION_CODES })

/** A schema that accepts any value `matches` accepts, and reports the issue for the others */
export const zMatch = <T>(
  matches: (value: unknown) => boolean,
  issue: (value: unknown) => ValidationIssueInput<DcqlValidationCode, DcqlValidationContexts>
) =>
  z.custom<T>().superRefine((value, ctx) => {
    if (!matches(value)) addDcqlIssue(ctx, issue(value))
  })

/**
 * The first schema when `isFirst` holds for the value, else the second, so the issues are those of the
 * schema the value is meant for, not the ones of a union
 */
export const zEither = <First extends z.ZodType, Second extends z.ZodType>(
  isFirst: (value: unknown) => boolean,
  first: First,
  second: Second
) =>
  z.custom<z.input<First> | z.input<Second>>().transform((value, ctx): z.output<First> | z.output<Second> => {
    const result = (isFirst(value) ? first : second).safeParse(value, { reportInput: true })
    if (result.success) return result.data
    ctx.issues.push(...(result.error.issues as z.core.$ZodRawIssue[]))
    return z.NEVER
  })

/** A value of one of the given JSON types, else an `invalid_type` issue */
export const zJsonTypes = <T>(expected: string, matches: (value: unknown) => boolean) =>
  z.custom<T>().superRefine((value, ctx) => {
    if (matches(value)) return
    addDcqlIssue(ctx, { code: 'invalid_type', message: `Expected ${expected}`, context: { expected } })
  })

export const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

/**
 * Parse the input with the schema, and throw a {@link DcqlParseError} with the issues when it does not match.
 */
export function parseWithIssues<Schema extends z.ZodType>(
  schema: Schema,
  input: unknown,
  description: string
): z.output<Schema> {
  const result = parseDcql(schema, input)
  if (result.success) return result.data

  throw new DcqlParseError({
    message: validationErrorMessage(`Invalid ${description}`, result.issues),
    issues: result.issues,
  })
}
