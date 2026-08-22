import { Tag } from 'cbor-x'
import { DataItem } from './data-item'

const MAX_DESCRIBED_STRING_LENGTH = 40

/**
 * Describes a decoded CBOR value in a form suitable for error messages, so a caller can tell
 * what their input actually was instead of only learning what it wasn't.
 *
 * Only describes the shape of the top-level value; it does not recurse into containers.
 */
export function describeCborValue(value: unknown): string {
  if (value === null) return 'null'
  if (value === undefined) return 'undefined'

  if (value instanceof Tag) return `a CBOR value tagged with tag ${value.tag}`
  if (value instanceof DataItem) return 'an encoded CBOR data item (tag 24)'

  if (Array.isArray(value)) {
    return `an untagged array with ${value.length} ${value.length === 1 ? 'element' : 'elements'}`
  }
  if (value instanceof Map) return `an untagged map with ${value.size} ${value.size === 1 ? 'entry' : 'entries'}`
  if (value instanceof Uint8Array) return `a byte string of ${value.length} bytes`

  if (typeof value === 'string') {
    const truncated =
      value.length > MAX_DESCRIBED_STRING_LENGTH ? `${value.slice(0, MAX_DESCRIBED_STRING_LENGTH)}…` : value
    return `the text string '${truncated}'`
  }

  if (typeof value === 'object') return `a value of type ${value.constructor?.name ?? 'object'}`

  return `the ${typeof value} value '${String(value)}'`
}
