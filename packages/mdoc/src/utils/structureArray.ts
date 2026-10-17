import type { AnyTypedMap } from '@owf/cose'

/**
 * `typedMap` decode and encode hooks for a key whose value is an array of nested structures, such as
 * the use cases of a `DeviceRequestInfo`. Decoding turns each encoded map into its structure with
 * `decode`, encoding turns each structure back into its encoded map. A value that is not an array is
 * left as is, for the schema to reject.
 */
export const structureArrayHooks = <Structure extends { encodedStructure: unknown }>(
  key: string,
  decode: (encoded: unknown) => Structure
) => ({
  decode: (input: Map<unknown, unknown>, originalDecode: (input: Map<unknown, unknown>) => AnyTypedMap) => {
    const map = originalDecode(input)
    const value = input.get(key)
    if (Array.isArray(value)) map.set(key, value.map(decode))
    return map
  },
  encode: (output: AnyTypedMap, originalEncode: (output: AnyTypedMap) => Map<unknown, unknown>) => {
    const map = originalEncode(output)
    const value: unknown = output.get(key)
    if (Array.isArray(value))
      map.set(
        key,
        (value as Array<Structure>).map((structure) => structure.encodedStructure)
      )
    return map
  },
})
