import { describe, expect, it } from 'vitest'
import { z } from 'zod'
import {
  addValidationIssue,
  hasValidationErrors,
  parseWithSchema,
  prefixIssuePaths,
  SCHEMA_VALIDATION_CODES,
  toValidationResult,
  VALIDATION_CODES,
  type ValidationIssue,
  type ValidationIssueOf,
  ValidationIssues,
  validationErrorMessage,
  validationErrors,
  zTyp,
} from '../../src'

describe('validation issues', () => {
  it('should only count errors as invalid', () => {
    const warning: ValidationIssue = { severity: 'warning', code: 'c', path: [], message: 'm' }
    const info: ValidationIssue = { severity: 'info', code: 'c', path: [], message: 'm' }
    const error: ValidationIssue = { severity: 'error', code: 'c', path: [], message: 'm' }
    expect(hasValidationErrors([])).toBe(false)
    expect(hasValidationErrors([warning, info])).toBe(false)
    expect(hasValidationErrors([warning, error])).toBe(true)
    expect(toValidationResult([warning, info])).toEqual({ valid: true, issues: [warning, info] })
    expect(toValidationResult([error])).toEqual({ valid: false, issues: [error] })
    expect(validationErrors(toValidationResult([warning, error, info]))).toEqual([error])
  })

  it('should put the issues below a path', () => {
    expect(prefixIssuePaths('payload', [{ severity: 'error', code: 'c', path: ['sub'], message: 'm' }])).toEqual([
      { severity: 'error', code: 'c', path: ['payload', 'sub'], message: 'm' },
    ])
  })

  it('should narrow the context by the code', () => {
    const issues: ValidationIssueOf<'expired' | 'other', { other: { reason: string } }>[] = [
      { severity: 'error', code: 'expired', path: ['exp'], message: 'm', context: { expiredAt: new Date(0) } },
      { severity: 'error', code: 'other', path: [], message: 'm', context: { reason: 'r' } },
    ]
    expect(issues.flatMap((issue) => (issue.code === 'expired' ? [issue.context.expiredAt] : []))).toEqual([
      new Date(0),
    ])
    // Each code narrows to its own context, also by elimination
    const reasons = issues.map((issue) =>
      issue.code === 'other' ? issue.context.reason : issue.context.expiredAt.toISOString()
    )
    expect(reasons).toEqual([new Date(0).toISOString(), 'r'])
    // @ts-expect-error not a code of these issues
    expect(issues.some((issue) => issue.code === 'not_a_code')).toBe(false)
  })

  it('should collect issues as errors with an empty path unless given', () => {
    const issues = new ValidationIssues<'expired' | 'missing_name'>()
    issues.add({ code: 'missing_name', message: 'Name is missing' })
    issues.add({
      code: 'expired',
      severity: 'warning',
      path: ['exp'],
      message: 'm',
      context: { expiredAt: new Date(0) },
    })
    // @ts-expect-error the context of `expired` is required
    issues.add({ code: 'expired', message: 'm' })
    // @ts-expect-error a code that is not one of the validator
    issues.add({ code: 'other', message: 'm' })
    expect(issues.result()).toEqual({
      valid: false,
      issues: [
        { severity: 'error', code: 'missing_name', path: [], message: 'Name is missing' },
        { severity: 'warning', code: 'expired', path: ['exp'], message: 'm', context: { expiredAt: new Date(0) } },
        { severity: 'error', code: 'expired', path: [], message: 'm' },
        { severity: 'error', code: 'other', path: [], message: 'm' },
      ],
    })
  })
})

describe('validationErrorMessage', () => {
  it('should list the errors with their path below the message', () => {
    const error: ValidationIssue = { severity: 'error', code: 'c', path: ['a', 0], message: 'is wrong' }
    const warning: ValidationIssue = { severity: 'warning', code: 'w', path: [], message: 'is odd' }
    const whole: ValidationIssue = { severity: 'error', code: 'c', path: [], message: 'is empty' }
    expect(validationErrorMessage('Invalid value', [warning, error, whole])).toBe(
      'Invalid value\na.0: is wrong\nis empty'
    )
    expect(validationErrorMessage('Invalid value', [warning])).toBe('Invalid value')
  })
})

describe('zod', () => {
  const issuesOf = (schema: z.ZodType, value: unknown) => {
    const result = parseWithSchema(schema, value, { codes: VALIDATION_CODES })
    return result.success ? [] : result.issues
  }

  it('should give the issues zod reports a code of SCHEMA_VALIDATION_CODES with its context', () => {
    const schema = z
      .object({
        name: z.string(),
        age: z.number().int(),
        country: z.string().length(2),
        kind: z.enum(['legal', 'natural']),
        uri: z.url(),
        tags: z.array(z.string()).min(1).max(2),
        id: z.union([z.string(), z.number()]),
        removed: z.undefined(),
      })
      .strict()
    const codesOf = (value: unknown) =>
      issuesOf(schema, value).map(({ code, path, context }) => ({ code, path, ...(context ? { context } : {}) }))

    expect(
      codesOf({ age: 1.5, country: 'NLD', kind: 'other', uri: 'nope', tags: [], id: true, removed: 1, extra: 1 })
    ).toEqual([
      { code: 'missing', path: ['name'] },
      { code: 'invalid_type', path: ['age'], context: { expected: 'int' } },
      { code: 'too_big', path: ['country'], context: { maximum: 2, inclusive: true, origin: 'string' } },
      { code: 'invalid_value', path: ['kind'], context: { allowed: ['legal', 'natural'] } },
      { code: 'invalid_format', path: ['uri'], context: { format: 'url' } },
      { code: 'too_small', path: ['tags'], context: { minimum: 1, inclusive: true, origin: 'array' } },
      { code: 'invalid_value', path: ['id'], context: {} },
      { code: 'not_allowed', path: ['removed'] },
      { code: 'unrecognized_keys', path: [], context: { keys: ['extra'] } },
    ])
    expect(Object.values(SCHEMA_VALIDATION_CODES)).not.toContain('custom')
  })

  it('should keep array indices as numbers', () => {
    expect(issuesOf(z.array(z.object({ name: z.string() })), [{ name: 1 }])[0].path).toEqual([0, 'name'])
  })

  it('should throw for a custom issue without a code of the validator, instead of dropping it', () => {
    expect(() =>
      issuesOf(
        z.string().refine((value) => value === 'a'),
        'b'
      )
    ).toThrow(/no validation code/)
    const schema = z.string().superRefine((_, ctx) => addValidationIssue<'other'>(ctx, { code: 'other', message: 'm' }))
    expect(() => issuesOf(schema, 'b')).toThrow(/'other', which is not a code of the validator/)
    expect(parseWithSchema(schema, 'b', { codes: { OTHER: 'other' } })).toEqual({
      success: false,
      issues: [{ severity: 'error', code: 'other', path: [], message: 'm' }],
    })
  })

  it('should give the parsed value when the schema passes', () => {
    expect(parseWithSchema(z.object({ a: z.string() }), { a: 'b', c: 1 })).toEqual({ success: true, data: { a: 'b' } })
  })

  it('should add an issue with its code and context at the path of the refined value', () => {
    const schema = z.object({
      period: z.object({ from: z.number(), until: z.number() }).superRefine((period, ctx) => {
        if (period.until > period.from) return
        addValidationIssue(ctx, {
          code: VALIDATION_CODES.EXPIRES_BEFORE_ISSUED,
          severity: 'warning',
          path: ['until'],
          message: 'until must be after from',
          requirement: 'REQ-1',
          context: { issuedAt: new Date(period.from), expiresAt: new Date(period.until) },
        })
      }),
    })
    expect(issuesOf(schema, { period: { from: 2, until: 1 } })).toEqual([
      {
        severity: 'warning',
        code: 'expires_before_issued',
        path: ['period', 'until'],
        message: 'until must be after from',
        requirement: 'REQ-1',
        context: { issuedAt: new Date(2), expiresAt: new Date(1) },
      },
    ])
  })

  it('should report a typ that is not expected as invalid_typ', () => {
    const schema = z.object({ typ: zTyp('dc+sd-jwt', 'vc+sd-jwt') })
    expect(schema.parse({ typ: 'vc+sd-jwt' })).toEqual({ typ: 'vc+sd-jwt' })
    expect(issuesOf(schema, { typ: 'JWT' })).toEqual([
      {
        severity: 'error',
        code: 'invalid_typ',
        path: ['typ'],
        message: 'typ must be dc+sd-jwt or vc+sd-jwt',
        context: { expected: ['dc+sd-jwt', 'vc+sd-jwt'], actual: 'JWT' },
      },
    ])
    expect(issuesOf(schema, {})[0].message).toBe('typ is missing, it must be dc+sd-jwt or vc+sd-jwt')
  })
})
