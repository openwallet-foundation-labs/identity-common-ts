import { describe, expect, it } from 'vitest'
import { z } from 'zod'
import { typedMap } from './typed-map'

enum ClaimKey {
  Subject = 2,
  ExpirationTime = 4,
}

const parse = (
  schema: { safeParse: (input: unknown) => z.ZodSafeParseResult<unknown> },
  map: Map<unknown, unknown>
) => {
  const result = schema.safeParse(map)
  return result.success
    ? undefined
    : result.error.issues.map((i) => {
        const { pathLabels } = i as { pathLabels?: unknown[] }
        return `${i.message} @ ${i.path.join('.')} (${pathLabels?.join('.')})`
      })
}

describe('typedMap key labels', () => {
  const entries = [
    [ClaimKey.Subject, z.string().exactOptional()],
    [ClaimKey.ExpirationTime, z.number()],
  ] as const

  it('names a missing required key', () => {
    expect(parse(typedMap(entries, { keyLabels: ClaimKey }), new Map())).toStrictEqual([
      "Expected key 'ExpirationTime (4)' to be defined. @ 4 (ExpirationTime (4))",
    ])
  })

  it('names the key an invalid value sits under', () => {
    expect(parse(typedMap(entries, { keyLabels: ClaimKey }), new Map([[4, 'not-a-number']]))).toStrictEqual([
      'expected number, received string @ 4 (ExpirationTime (4))',
    ])
  })

  it('reports the unexpected keys in one issue at the map, naming the ones known to the labels', () => {
    const schema = typedMap(entries, { keyLabels: { ...ClaimKey, 9: 'Scope' }, allowAdditionalKeys: false })
    const map = new Map<unknown, unknown>([
      [4, 1],
      [9, 'x'],
      [10, 'y'],
    ])

    expect(schema.safeParse(map).error?.issues).toMatchObject([
      {
        code: 'unrecognized_keys',
        path: [],
        keys: [9, 10],
        message: "Unexpected keys 'Scope (9)', '10' found in map, additional keys are not allowed.",
      },
    ])
  })

  it('falls back to the raw label without keyLabels', () => {
    expect(parse(typedMap(entries), new Map())).toStrictEqual(["Expected key '4' to be defined. @ 4 (4)"])
  })

  it('labels the keys of a nested typed map below the key of the outer one', () => {
    const outer = typedMap([[1, typedMap(entries, { keyLabels: ClaimKey })]] as const, { keyLabels: { 1: 'Claims' } })

    expect(parse(outer, new Map([[1, new Map([[4, 'x']])]]))).toStrictEqual([
      'expected number, received string @ 1.4 (Claims (1).ExpirationTime (4))',
    ])
  })

  it('does not mistake an enum forward mapping for a name', () => {
    // `ClaimKey.ExpirationTime` is 4, so `ClaimKey['ExpirationTime']` is a number, not a name
    const schema = typedMap([['ExpirationTime', z.number()]] as const, { keyLabels: ClaimKey })

    expect(parse(schema, new Map())).toStrictEqual([
      "Expected key 'ExpirationTime' to be defined. @ ExpirationTime (ExpirationTime)",
    ])
  })
})
