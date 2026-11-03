/** Whether `key` is an own property of `object`, so `constructor` or `toString` are not found everywhere. */
export const hasOwn = (object: object, key: PropertyKey): boolean =>
  // biome-ignore lint/suspicious/noPrototypeBuiltins: `Object.hasOwn` is not in the ES2020 lib this package targets
  Object.prototype.hasOwnProperty.call(object, key)

/**
 * Whether two JSON values are the same value: arrays holding the same values in the same order, and
 * objects with the same members, in whatever order. A member set to `undefined` counts as absent, as
 * it is once serialized.
 */
export function isSameJsonValue(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((value, index) => isSameJsonValue(value, b[index]))
    )
  }

  if (typeof a === 'object' && a !== null && typeof b === 'object' && b !== null) {
    const membersOf = (object: object) =>
      Object.keys(object).filter((member) => (object as Record<string, unknown>)[member] !== undefined)
    const membersOfA = membersOf(a)

    return (
      membersOfA.length === membersOf(b).length &&
      membersOfA.every(
        (member) =>
          hasOwn(b, member) &&
          isSameJsonValue((a as Record<string, unknown>)[member], (b as Record<string, unknown>)[member])
      )
    )
  }

  return a === b
}
