// Bare 'cbor-x' resolves to a Node build that loads native cbor-extract (child_process) in edge runtimes; its subpaths are pure JS
import type { Tag as CborXTag } from 'cbor-x'
import * as cborXDecode from 'cbor-x/decode'

export type { Options } from 'cbor-x'
export { addExtension, Encoder } from 'cbor-x/encode'

// `cbor-x/decode` exports `Tag` at runtime, but its type declarations omit it
export const Tag = (cborXDecode as unknown as { Tag: typeof CborXTag }).Tag
export type Tag = CborXTag
