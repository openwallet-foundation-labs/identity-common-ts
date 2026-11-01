import { IdentityException } from '@owf/identity-common'

/**
 * SLException is a custom error class for Status List related exceptions.
 */
export class SLException extends IdentityException {
  constructor(message: string, details?: unknown) {
    super(message, details)
    Object.setPrototypeOf(this, SLException.prototype)
    this.name = 'SLException'
  }
}

/**
 * The status at an index of a status list that verified is not Valid. Unlike other `SLException`s,
 * this is a statement about the referenced token rather than about a status list that fails
 * verification (Token Status List § 7 and § 8.3), so `idx` and `status` are carried as data.
 */
export class StatusListEntryNotValidException extends SLException {
  public readonly idx: number
  /** The status at `idx`, e.g. `1` for Invalid (revoked) or `2` for Suspended. */
  public readonly status: number

  constructor(message: string, { idx, status }: { idx: number; status: number }) {
    super(message, { idx, status })
    Object.setPrototypeOf(this, StatusListEntryNotValidException.prototype)
    this.name = 'StatusListEntryNotValidException'
    this.idx = idx
    this.status = status
  }
}
