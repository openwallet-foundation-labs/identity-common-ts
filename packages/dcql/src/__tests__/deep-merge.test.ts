import { describe, expect, it } from 'vitest'
import { DcqlError } from '../dcql-error/index.js'
import { DcqlNotDisclosed } from '../u-dcql.js'
import { deepMerge } from '../util/deep-merge.js'

describe('deepMerge', () => {
  it('merges arrays filling undisclosed gaps with DcqlNotDisclosed', () => {
    const claim1 = { list: [DcqlNotDisclosed, null] }
    const claim2 = { list: [DcqlNotDisclosed, DcqlNotDisclosed, DcqlNotDisclosed, 'fourth'] }

    const merged = deepMerge(claim1, {})
    const fullMerged = deepMerge(claim2, merged) as { list: unknown[] }

    expect(fullMerged.list).toStrictEqual([DcqlNotDisclosed, null, DcqlNotDisclosed, 'fourth'])
    expect(0 in fullMerged.list).toBe(true)
    expect(1 in fullMerged.list).toBe(true)
    expect(2 in fullMerged.list).toBe(true)
    expect(3 in fullMerged.list).toBe(true)
    expect(fullMerged.list[0]).toBe(DcqlNotDisclosed)
    expect(fullMerged.list[1]).toBe(null)
    expect(fullMerged.list[2]).toBe(DcqlNotDisclosed)
    expect(fullMerged.list[3]).toBe('fourth')
  })

  it('throws when target value is a primitive but source value is an object or array', () => {
    expect(() => deepMerge({ a: { b: 1 } }, { a: 'x' })).toThrow(DcqlError)
    expect(() => deepMerge({ a: { b: 1 } }, { a: 'x' })).toThrow(
      'target value provided to deepMerge is neither an array or object.'
    )
  })

  it('correctly merges literal null values without overriding with undisclosed symbol', () => {
    const merged = deepMerge({ a: null }, { a: DcqlNotDisclosed })
    expect(merged).toStrictEqual({ a: null })
  })

  it.each(['constructor', 'toString', 'hasOwnProperty'])('merges a claim named %s as an own property', (key) => {
    const merged = deepMerge({ [key]: { a: 1 } }, {})
    const fullMerged = deepMerge({ [key]: { b: [2] } }, merged) as Record<string, unknown>

    expect(Object.keys(fullMerged)).toStrictEqual([key])
    expect(fullMerged[key]).toStrictEqual({ a: 1, b: [2] })
    expect(Object.getPrototypeOf(fullMerged)).toBe(Object.prototype)
  })

  it('merges a __proto__ claim as an own property without changing the prototype', () => {
    const merged = deepMerge(JSON.parse('{"__proto__": {"polluted": true}}'), {}) as Record<string, unknown>

    expect(Object.getPrototypeOf(merged)).toBe(Object.prototype)
    expect(Object.getOwnPropertyDescriptor(merged, '__proto__')?.value).toStrictEqual({ polluted: true })
    expect(({} as Record<string, unknown>).polluted).toBeUndefined()
  })
})
