import { Encoder, type Options } from 'cbor-x'
import { DataItem } from './data-item'
import { CborDecodeError, CborEncodeError } from './error'

export type CborOptions = Options & {
  unwrapTopLevelDataItem?: boolean
}

const encoderDefaults: CborOptions = {
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
  unwrapTopLevelDataItem: true,
  variableMapSize: true,
}

export const cborDecode = <T>(input: Uint8Array, options: CborOptions = encoderDefaults): T => {
  const params = { ...encoderDefaults, ...options }
  const enc = new Encoder(params)

  let decoded: unknown
  try {
    decoded = enc.decode(input)
  } catch (error) {
    // cbor-x errors ('Data read, but end of buffer not reached', 'Unexpected end of CBOR data',
    // ...) give no indication of what was being decoded. Wrap them so callers can tell a
    // malformed input apart from a structurally valid one that failed validation later on.
    throw new CborDecodeError(
      `Unable to decode ${input.length} bytes as CBOR: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error }
    )
  }

  return params.unwrapTopLevelDataItem && typeof decoded === 'object' && decoded instanceof DataItem
    ? (decoded.data as T)
    : (decoded as T)
}

export const cborEncode = (obj: unknown, options: Options = encoderDefaults): Uint8Array => {
  const params = { ...encoderDefaults, ...options }
  const enc = new Encoder(params)

  try {
    return Uint8Array.from(enc.encode(obj))
  } catch (error) {
    throw new CborEncodeError(
      `Unable to encode value as CBOR: ${error instanceof Error ? error.message : String(error)}`,
      {
        cause: error,
      }
    )
  }
}
