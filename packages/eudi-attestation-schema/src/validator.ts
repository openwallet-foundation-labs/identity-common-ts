import { SchemaMetaError } from './schema-meta-error'
import { zSchemaMeta } from './schemas'
import type { SchemaMeta } from './types'

export interface ValidationError {
  path: string
  message: string
}

export interface ValidationResult {
  valid: boolean
  errors: ValidationError[]
}

/**
 * Validate a SchemaMeta object against the TS11 schema
 */
export function validateSchemaMeta(schemaMetaDocument: unknown): ValidationResult {
  const result = zSchemaMeta.safeParse(schemaMetaDocument)

  if (result.success) {
    return { valid: true, errors: [] }
  }

  const errors: ValidationError[] = result.error.issues.map((issue) => ({
    path: issue.path.join('.'),
    message: issue.message,
  }))

  return { valid: false, errors }
}

/**
 * Assert that a SchemaMeta object is valid, throwing if not
 */
export function assertValidSchemaMeta(schemaMetaDocument: unknown): asserts schemaMetaDocument is SchemaMeta {
  const result = validateSchemaMeta(schemaMetaDocument)
  if (!result.valid) {
    const errorMessages = result.errors.map((e) => `${e.path}: ${e.message}`).join('\n')
    throw new SchemaMetaError(`Invalid SchemaMeta:\n${errorMessages}`)
  }
}
