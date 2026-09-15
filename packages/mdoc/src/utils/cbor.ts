import { cborDecode, DataItem } from '@owf/cose'

/**
 * The bytes of an encoded structure, without the tag 24 (encoded CBOR data item) it may be wrapped in.
 */
export const unwrapDataItemBytes = (bytes: Uint8Array) => {
  const decoded = cborDecode(bytes, { unwrapTopLevelDataItem: false })
  return new Uint8Array(decoded instanceof DataItem ? decoded.buffer : bytes)
}
