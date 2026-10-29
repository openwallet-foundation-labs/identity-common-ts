import { DcqlError } from '../dcql-error'
import { DcqlNotDisclosed } from '../u-dcql'

/**
 * Deep merge two objects. Undisclosed/empty slots (DcqlNotDisclosed or undefined)
 * will be overridden if there is a value in one of the two objects.
 * Objects can also be arrays, but otherwise only primitive types are allowed.
 */
function isMergeableObject(val: unknown): val is Array<unknown> | Record<string, unknown> {
  return (
    val !== null && typeof val === 'object' && (Object.getPrototypeOf(val) === Object.prototype || Array.isArray(val))
  )
}

function hasOwn(val: object, key: string | number) {
  // biome-ignore lint/suspicious/noPrototypeBuiltins: `Object.hasOwn` is not in the ES2020 lib this package targets
  return Object.prototype.hasOwnProperty.call(val, key)
}

export function deepMerge(source: Array<unknown> | object, target: Array<unknown> | object): Array<unknown> | object {
  let newTarget = target

  if (!isMergeableObject(source)) {
    throw new DcqlError({
      message: 'source value provided to deepMerge is neither an array or object.',
      code: 'PARSE_ERROR',
    })
  }
  if (!isMergeableObject(target)) {
    throw new DcqlError({
      message: 'target value provided to deepMerge is neither an array or object.',
      code: 'PARSE_ERROR',
    })
  }

  for (const [key, val] of Object.entries(source)) {
    if (isMergeableObject(val)) {
      // Only own properties, so a claim such as `constructor` does not resolve to a member of `Object.prototype`
      const targetVal = hasOwn(newTarget, key) ? (newTarget as Record<string, unknown>)[key] : undefined
      if (targetVal !== undefined && targetVal !== DcqlNotDisclosed && !isMergeableObject(targetVal)) {
        throw new DcqlError({
          message: 'target value provided to deepMerge is neither an array or object.',
          code: 'PARSE_ERROR',
        })
      }
      const validTarget = isMergeableObject(targetVal) ? targetVal : new (Object.getPrototypeOf(val).constructor)()
      const newValue = deepMerge(val, validTarget as Array<unknown> | object)
      newTarget = setValue(newTarget, key, newValue)
    } else if (val !== DcqlNotDisclosed && val !== undefined) {
      newTarget = setValue(newTarget, key, val)
    }
  }
  return newTarget
}

// biome-ignore lint/suspicious/noExplicitAny: value can be anything
function setValue(target: any, key: string, value: any) {
  let newTarget = target

  if (Array.isArray(newTarget)) {
    const index = Number(key)
    newTarget = Array.from({ length: Math.max(newTarget.length, index + 1) }, (_, i) =>
      hasOwn(newTarget, i) ? newTarget[i] : DcqlNotDisclosed
    )
    newTarget[index] = value
  } else if (Object.getPrototypeOf(newTarget) === Object.prototype) {
    newTarget = { ...newTarget, [key]: value }
  } else {
    throw new DcqlError({
      message: 'Unsupported type for deep merge. Only primitive types or Array and Object are supported',
      code: 'INTERNAL_SERVER_ERROR',
    })
  }

  return newTarget
}
