export type Path = readonly (string | number)[]

/** A key to look a path up in a map */
export const pathKey = (path: Path): string => JSON.stringify(path)

/** A path for display, e.g. `providers[0].services[1].serviceStatus` */
export function formatPath(path: Path): string {
  if (path.length === 0) return '(document)'
  return path.map((key, index) => (typeof key === 'number' ? `[${key}]` : index === 0 ? key : `.${key}`)).join('')
}

/**
 * Split a path into the longest prefix that exists in the value, where a finding can be
 * shown, and the rest, which names an element that is not present.
 */
export function anchorOf(value: unknown, path: Path): { anchor: Path; missing: Path } {
  let current = value
  let depth = 0
  for (const key of path) {
    if (typeof current !== 'object' || current === null || !(key in current)) break
    current = (current as Record<string | number, unknown>)[key]
    depth++
  }
  return { anchor: path.slice(0, depth), missing: path.slice(depth) }
}
