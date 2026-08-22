// biome-ignore format: no explanation
class CborError extends Error {
  // NOTE: declared explicitly rather than passing `{ cause }` to `super`, as the
  // project targets ES2020 and `Error.cause` was only added in ES2022.
  public readonly cause?: unknown

  constructor(message: string = new.target.name, options?: { cause?: unknown }) {
    super(message)
    this.name = new.target.name
    this.cause = options?.cause
  }
}

export class CborDecodeError extends CborError {}
export class CborEncodeError extends CborError {}
