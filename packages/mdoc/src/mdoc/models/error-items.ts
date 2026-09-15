import { CborStructure } from '@owf/cose'
import z from 'zod'
import type { DataElementIdentifier } from './data-element-identifier'
import type { ErrorCode } from './error-code'

export const errorItemsSchema = z.map(z.string(), z.number())
export type ErrorItemsStructure = Map<DataElementIdentifier, ErrorCode>

export type ErrorItemsOptions = {
  errorItems: ErrorItemsStructure
}

export class ErrorItems extends CborStructure<ErrorItemsStructure> {
  public static override get encodingSchema() {
    return errorItemsSchema
  }

  public get errorItems() {
    return this.structure
  }

  public getErrorCode(dataElementIdentifier: DataElementIdentifier) {
    return this.structure.get(dataElementIdentifier)
  }

  public static create(options: ErrorItemsOptions) {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(options.errorItems)
  }
}
