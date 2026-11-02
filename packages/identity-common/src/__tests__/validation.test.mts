import { describe, expect, it } from 'vitest'
import {
  hasValidationErrors,
  prefixIssuePaths,
  schemaIssueToValidationIssue,
  toValidationResult,
  VALIDATION_CODES,
  type ValidationIssue,
  type ValidationIssueOf,
  validationErrors,
} from '../../src'

describe('validation issues', () => {
  it('should convert a schema issue into an error', () => {
    expect(
      schemaIssueToValidationIssue({ code: 'invalid_type', path: ['providers', 0, 'name'], message: 'Expected string' })
    ).toEqual({ severity: 'error', code: 'invalid_type', path: ['providers', 0, 'name'], message: 'Expected string' })
  })

  it('should keep array indices as numbers and stringify symbols', () => {
    const key = Symbol('key')
    expect(schemaIssueToValidationIssue({ code: 'custom', path: [key, 1], message: 'm' }, 'warning')).toEqual({
      severity: 'warning',
      code: 'custom',
      path: ['Symbol(key)', 1],
      message: 'm',
    })
  })

  it('should take the code, severity, requirement and context of a custom issue from its params', () => {
    const context = { expected: ['rc-wrp+jwt'], actual: 'JWT' }
    expect(
      schemaIssueToValidationIssue({
        code: 'custom',
        path: ['typ'],
        message: 'typ must be rc-wrp+jwt',
        params: { code: VALIDATION_CODES.INVALID_TYP, severity: 'warning', requirement: 'GEN-5.2.3-01', context },
      })
    ).toEqual({
      severity: 'warning',
      code: 'invalid_typ',
      path: ['typ'],
      message: 'typ must be rc-wrp+jwt',
      requirement: 'GEN-5.2.3-01',
      context,
    })
  })

  it('should keep the schema code when the params carry no code', () => {
    expect(schemaIssueToValidationIssue({ code: 'custom', path: [], message: 'm', params: { other: 1 } })).toEqual({
      severity: 'error',
      code: 'custom',
      path: [],
      message: 'm',
    })
  })

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

  it('should narrow the context of a common code', () => {
    const issues: ValidationIssueOf<'expired' | 'other'>[] = [
      { severity: 'error', code: 'expired', path: ['exp'], message: 'm', context: { expiredAt: new Date(0) } },
      { severity: 'error', code: 'other', path: [], message: 'm' },
    ]
    const expired = issues.flatMap((issue) => (issue.code === 'expired' ? [issue.context.expiredAt] : []))
    expect(expired).toEqual([new Date(0)])
  })
})
