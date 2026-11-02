import { IdentityError } from '@owf/identity-common'

/**
 * StatusListError is a custom error class for Status List related errors.
 */
export class StatusListError extends IdentityError {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, StatusListError.prototype)
    this.name = 'StatusListError'
  }
}

/**
 * The status at an index of a status list that verified is not Valid. Unlike other `StatusListError`s,
 * this is a statement about the referenced token rather than about a status list that fails
 * verification (Token Status List § 7 and § 8.3), so `idx` and `status` are carried as data.
 */
export class StatusListEntryNotValidError extends StatusListError {
  public readonly idx: number
  /** The status at `idx`, e.g. `1` for Invalid (revoked) or `2` for Suspended. */
  public readonly status: number

  constructor(message: string, { idx, status }: { idx: number; status: number }) {
    super(message, { idx, status })
    Object.setPrototypeOf(this, StatusListEntryNotValidError.prototype)
    this.name = 'StatusListEntryNotValidError'
    this.idx = idx
    this.status = status
  }
}
