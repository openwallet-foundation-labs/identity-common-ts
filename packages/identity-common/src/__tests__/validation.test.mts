import { describe, expect, it } from 'vitest'
import { z } from 'zod'
import {
  addValidationIssue,
  hasValidationErrors,
  IdentityError,
  parseWithErrorHandling,
  parseWithSchema,
  prefixIssuePaths,
  SCHEMA_VALIDATION_CODES,
  toValidationResult,
  VALIDATION_CODES,
  ValidationError,
  type ValidationIssue,
  type ValidationIssueOf,
  ValidationIssues,
  validationErrorMessage,
  validationErrors,
  zNumericDate,
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
  it('should list the errors with their path and code below the message, and leave out the warnings', () => {
    const error: ValidationIssue = {
      severity: 'error',
      code: 'invalid_type',
      path: ['tags', 0],
      message: 'expected string, received number',
    }
    const warning: ValidationIssue = {
      severity: 'warning',
      code: 'deprecated',
      path: ['kind'],
      message: 'is deprecated',
    }
    const whole: ValidationIssue = {
      severity: 'error',
      code: 'unrecognized_keys',
      path: [],
      message: 'unrecognized key: "x"',
    }
    expect(validationErrorMessage('Invalid value', [warning, error, whole])).toBe(
      'Invalid value\n  - tags.0: expected string, received number (invalid_type)\n  - unrecognized key: "x" (unrecognized_keys)'
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
      { code: 'missing_value', path: ['name'], context: { expected: 'string' } },
      { code: 'invalid_type', path: ['age'], context: { expected: 'int' } },
      { code: 'too_big', path: ['country'], context: { maximum: 2, inclusive: true, origin: 'string' } },
      { code: 'invalid_value', path: ['kind'], context: { allowed: ['legal', 'natural'] } },
      { code: 'invalid_format', path: ['uri'], context: { format: 'url' } },
      { code: 'too_small', path: ['tags'], context: { minimum: 1, inclusive: true, origin: 'array' } },
      { code: 'invalid_value', path: ['id'], context: { branches: expect.any(Array) } },
      { code: 'not_allowed', path: ['removed'] },
      { code: 'unrecognized_keys', path: [], context: { keys: ['extra'] } },
    ])
    expect(Object.values(SCHEMA_VALIDATION_CODES)).not.toContain('custom')
  })

  it('should give a union that no member matches the issues of each member, below its path', () => {
    const a = z.object({ type: z.literal('a'), x: z.string() })
    const b = z.object({ type: z.literal('b'), y: z.number() })
    expect(issuesOf(z.object({ v: z.union([a, b]) }), { v: { type: 'a', x: 1 } })).toEqual([
      {
        severity: 'error',
        code: 'invalid_value',
        path: ['v'],
        message: 'Invalid input',
        context: {
          branches: [
            [expect.objectContaining({ code: 'invalid_type', path: ['v', 'x'], context: { expected: 'string' } })],
            [
              expect.objectContaining({ code: 'invalid_value', path: ['v', 'type'], context: { allowed: ['b'] } }),
              expect.objectContaining({ code: 'missing_value', path: ['v', 'y'], context: { expected: 'number' } }),
            ],
          ],
        },
      },
    ])
  })

  it('should name the types of a union whose members only differ in type', () => {
    const [issue] = issuesOf(z.object({ v: z.union([z.string(), z.array(z.string())]) }), { v: 1 })
    expect(issue).toMatchObject({
      code: 'invalid_value',
      path: ['v'],
      message: 'expected string or array',
    })
  })

  it('should list the options of a discriminated union whose discriminator matches none', () => {
    const a = z.object({ type: z.literal('a') })
    const b = z.object({ type: z.literal('b') })
    expect(issuesOf(z.discriminatedUnion('type', [a, b]), { type: 'c' })).toEqual([
      expect.objectContaining({ code: 'invalid_value', path: ['type'], context: { allowed: ['a', 'b'] } }),
    ])
  })

  it('should leave the prefix out of the messages of zod, as the code says it, and keep the ones of the schema', () => {
    const schema = z.object({
      tags: z.array(z.string()).min(1),
      kind: z.enum(['a', 'b']),
      name: z.string({ error: 'Invalid input: name must be a string' }),
    })
    expect(issuesOf(schema, { tags: [], kind: 'c', name: 1 }).map(({ message }) => message)).toEqual([
      'expected array to have >=1 items',
      'expected one of "a"|"b"',
      'Invalid input: name must be a string',
    ])
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

  it.each(['kb+jwt', 'KB+JWT', 'application/kb+jwt', 'Application/KB+JWT'])(
    'should accept typ %s as the JOSE media type kb+jwt, and keep it as received',
    (typ) => {
      expect(z.object({ typ: zTyp('kb+jwt') }).parse({ typ })).toEqual({ typ })
      expect(z.object({ typ: zTyp('application/kb+jwt') }).parse({ typ })).toEqual({ typ })
    }
  )

  // RFC 7515 section 4.1.9: a typ is a media type name, it has no parameters as a Content-Type does
  it('should reject a typ with media type parameters', () => {
    expect(issuesOf(z.object({ typ: zTyp('kb+jwt') }), { typ: 'kb+jwt; charset=utf-8' })[0].code).toBe('invalid_typ')
  })

  it('should report a typ that is not a string as invalid_typ', () => {
    expect(issuesOf(z.object({ typ: zTyp('kb+jwt') }), { typ: 1 })).toMatchObject([
      { code: 'invalid_typ', path: ['typ'], context: { expected: ['kb+jwt'], actual: 1 } },
    ])
  })
})

describe('pathLabels', () => {
  const issue: ValidationIssue = {
    severity: 'error',
    code: 'c',
    path: [4],
    pathLabels: ['ExpirationTime (4)'],
    message: 'is wrong',
  }

  it('should name the path with its labels in the message, and prefix them with the path', () => {
    expect(validationErrorMessage('Invalid', [issue])).toBe('Invalid\n  - ExpirationTime (4): is wrong (c)')
    expect(prefixIssuePaths('payload', [issue])).toEqual([
      { ...issue, path: ['payload', 4], pathLabels: ['payload', 'ExpirationTime (4)'] },
    ])
  })

  it('should label the end of the path of a zod issue, below the keys of the schemas around it', () => {
    const labelled = z.custom().superRefine((_, ctx) =>
      addValidationIssue(ctx, {
        code: 'invalid_value',
        path: [4],
        pathLabels: ['Exp (4)'],
        message: 'm',
        context: {},
      })
    )
    expect(parseWithSchema(z.object({ a: z.array(labelled) }), { a: [1] })).toMatchObject({
      issues: [{ path: ['a', 0, 4], pathLabels: ['a', 0, 'Exp (4)'] }],
    })
  })
})

describe('ValidationError', () => {
  const issues: ValidationIssue[] = [
    { severity: 'warning', code: 'c', path: ['a'], message: 'is odd' },
    { severity: 'error', code: 'c', path: ['b'], message: 'is wrong' },
  ]

  it('should be an IdentityError named after its class, listing the errors in its message', () => {
    const error = new ValidationError('Invalid value', issues)
    expect(error).toBeInstanceOf(IdentityError)
    expect(error.name).toBe('ValidationError')
    expect(error.message).toBe('Invalid value\n  - b: is wrong (c)')
    expect(error.issues).toBe(issues)
  })

  it('should keep instanceof and the name of a subclass', () => {
    class JwtValidationError extends ValidationError {}
    const error = new JwtValidationError('Invalid JWT', issues)
    expect(error).toBeInstanceOf(ValidationError)
    expect(error.name).toBe('JwtValidationError')
  })
})

describe('parseWithErrorHandling', () => {
  it('should give the parsed value', () => {
    expect(
      parseWithErrorHandling(
        z.string().transform((value) => value.length),
        'abc'
      )
    ).toBe(3)
  })

  it('should throw a ValidationError with the issues', () => {
    expect(() => parseWithErrorHandling(z.object({ age: z.number() }), {}, 'Invalid person')).toThrow(
      expect.objectContaining({
        name: 'ValidationError',
        message: 'Invalid person\n  - age: expected number, received undefined (missing_value)',
        issues: [
          {
            severity: 'error',
            code: 'missing_value',
            path: ['age'],
            message: 'expected number, received undefined',
            context: { expected: 'number' },
          },
        ],
      })
    )
  })

  it('should give a custom issue without a code invalid_value, as the schema may be one a caller passes in', () => {
    const schema = z.object({
      name: z.string().refine((name) => name === 'a', 'must be a'),
      typ: zTyp('JWT'),
    })
    expect(() => parseWithErrorHandling(schema, { name: 'b', typ: 'at+jwt' })).toThrow(
      expect.objectContaining({
        issues: [
          { severity: 'error', code: 'invalid_value', path: ['name'], message: 'must be a', context: {} },
          expect.objectContaining({ code: 'invalid_typ', path: ['typ'] }),
        ],
      })
    )
  })

  it.each([
    ['a number', z.number()],
    ['an enum', z.enum(['a', 'b'])],
    ['a literal', z.literal('a')],
    ['a url', z.url()],
    ['a pattern', z.string().regex(/^a/)],
    ['a maximum length', z.string().max(3)],
  ])('should leave the value out of the message when it is not %s', (_, schema) => {
    expect(() => parseWithErrorHandling(z.object({ secret: schema }), { secret: 'hunter2' })).toThrow(
      expect.objectContaining({ message: expect.not.stringContaining('hunter2') })
    )
  })
})

describe('zNumericDate', () => {
  it.each([0, -1, 1_700_000_000.5])('should accept %s', (value) => {
    expect(zNumericDate.parse(value)).toBe(value)
  })

  it.each(['1700000000', Number.NaN, Number.POSITIVE_INFINITY, null, new Date(0)])('should reject %s', (value) => {
    expect(zNumericDate.safeParse(value).success).toBe(false)
  })

  it('should say what it expects', () => {
    expect(() => parseWithErrorHandling(z.object({ exp: zNumericDate }), { exp: '1' })).toThrow(
      'exp: expected a NumericDate, the number of seconds since 1970-01-01T00:00:00Z'
    )
  })
})
