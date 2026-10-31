import { describe, expect, it } from 'vitest'
import { hasErrorFindings, schemaIssueToFinding } from '../../src'

describe('findings', () => {
  it('should convert a schema issue into an error finding', () => {
    expect(
      schemaIssueToFinding({ code: 'invalid_type', path: ['providers', 0, 'name'], message: 'Expected string' })
    ).toEqual({ severity: 'error', code: 'invalid_type', path: ['providers', 0, 'name'], message: 'Expected string' })
  })

  it('should keep array indices as numbers and stringify symbols', () => {
    const key = Symbol('key')
    expect(schemaIssueToFinding({ code: 'custom', path: [key, 1], message: 'm' }, 'warning')).toEqual({
      severity: 'warning',
      code: 'custom',
      path: ['Symbol(key)', 1],
      message: 'm',
    })
  })

  it('should only report errors as errors', () => {
    expect(hasErrorFindings([])).toBe(false)
    expect(hasErrorFindings([{ severity: 'warning', code: 'c', path: [], message: 'm' }])).toBe(false)
    expect(hasErrorFindings([{ severity: 'error', code: 'c', path: [], message: 'm' }])).toBe(true)
  })
})
