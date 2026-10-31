/**
 * A common shape for the outcome of a format or profile check, so the validators of
 * different packages can be consumed the same way, for example to show which element
 * of a parsed document conforms and which does not.
 */

/** `error` makes the checked value invalid; `warning` notes a deviation that does not */
export type FindingSeverity = 'error' | 'warning'

/** A single result of a format or profile check */
export interface Finding<Code extends string = string> {
  severity: FindingSeverity
  /** Stable, machine readable code to branch on instead of the message */
  code: Code
  /**
   * Location of the checked element in the validated value, as property names and array
   * indices. Empty when the finding concerns the value as a whole.
   */
  path: (string | number)[]
  message: string
  /** Requirement identifier of the specification the validator implements, e.g. `GEN-6.6.1-05` */
  requirement?: string
}

/**
 * The structural part of a schema validation issue, as reported by zod and similar
 * schema libraries, so this package does not depend on one of them.
 */
export interface SchemaIssue {
  code: string
  path: readonly PropertyKey[]
  message: string
}

/** Convert a schema validation issue into a finding */
export function schemaIssueToFinding(issue: SchemaIssue, severity: FindingSeverity = 'error'): Finding {
  return {
    severity,
    code: issue.code,
    path: issue.path.map((key) => (typeof key === 'number' ? key : String(key))),
    message: issue.message,
  }
}

/** Whether any of the findings is an error */
export function hasErrorFindings(findings: readonly Finding[]): boolean {
  return findings.some((finding) => finding.severity === 'error')
}
