import type { DcqlValidationIssue } from '../u-dcql.js'
import { DcqlError } from './e-base.js'

export class DcqlParseError extends DcqlError {
  /** The issues of the input that does not match the schema, empty when the error is not about the schema */
  public readonly issues: DcqlValidationIssue[]

  constructor({ issues = [], ...opts }: { message: string; cause?: unknown; issues?: DcqlValidationIssue[] }) {
    super({ code: 'PARSE_ERROR', ...opts })
    this.issues = issues
  }
}

export class DcqlInvalidClaimsQueryIdError extends DcqlError {
  constructor(opts: { message: string; cause?: unknown }) {
    super({ code: 'BAD_REQUEST', ...opts })
  }
}

export class DcqlMissingClaimSetParseError extends DcqlError {
  constructor(opts: { message: string; cause?: unknown }) {
    super({ code: 'PARSE_ERROR', ...opts })
  }
}

export class DcqlInvalidPresentationRecordError extends DcqlError {
  constructor(opts: { message: string; cause?: unknown }) {
    super({ code: 'BAD_REQUEST', ...opts })
  }
}

export class DcqlPresentationResultError extends DcqlError {
  constructor(opts: { message: string; cause?: unknown }) {
    super({ code: 'BAD_REQUEST', ...opts })
  }
}
