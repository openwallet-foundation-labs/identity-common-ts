/**
 * The value of an own property of `record`, so that a key such as `constructor` or `toString` does
 * not resolve to a property of `Object.prototype`. Namespaces and element identifiers come from the
 * device request, so they are used as keys as they are.
 */
export const getOwnProperty = <Value>(record: Record<string, Value> | undefined, key: string): Value | undefined =>
  // biome-ignore lint/suspicious/noPrototypeBuiltins: `Object.hasOwn` is not in the ES2020 lib this package targets
  record && Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined
