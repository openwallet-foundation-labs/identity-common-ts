import { CborStructure } from '@owf/cose'
import z from 'zod'
import { ErrorItems, zErrorItems } from './error-items'
import type { Namespace } from './namespace'

const zErrorsEncoded = z.map(z.string(), zErrorItems)
const zErrorsDecoded = z.map(z.string(), z.instanceof(ErrorItems))

export type ErrorsEncodedStructure = z.infer<typeof zErrorsEncoded>
export type ErrorsDecodedStructure = z.infer<typeof zErrorsDecoded>

export type ErrorsOptions = {
  errors: ErrorsDecodedStructure
}

export class Errors extends CborStructure<ErrorsEncodedStructure, ErrorsDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(zErrorsEncoded, zErrorsDecoded, {
      encode: (decoded) => {
        const errorsDecoded: ErrorsEncodedStructure = new Map()

        decoded.forEach((value, key) => {
          errorsDecoded.set(key, value.encodedStructure)
        })

        return errorsDecoded
      },
      decode: (encoded) => {
        const errorsDecoded: ErrorsDecodedStructure = new Map()

        encoded.forEach((value, key) => {
          errorsDecoded.set(key, ErrorItems.fromEncodedStructure(value))
        })

        return errorsDecoded
      },
    })
  }

  /**
   * Map where keys are namespaces and values are the errored data elements within that namespace
   */
  public get errors() {
    return this.structure
  }

  public getErrorItems(namespace: Namespace) {
    return this.structure.get(namespace)
  }

  public static create(options: ErrorsOptions) {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(options.errors)
  }
}
