import type { Tag as CborXTag } from 'cbor-x'
import * as cborXDecode from 'cbor-x/decode'

export type { Options } from 'cbor-x'
export { addExtension, Encoder } from 'cbor-x/encode'

export const Tag = (cborXDecode as unknown as { Tag: typeof CborXTag }).Tag
export type Tag = CborXTag
