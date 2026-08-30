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
  return result.success ? undefined : result.error.issues.map((i) => `${i.message} @ ${i.path.join('.')}`)
}

describe('typedMap key labels', () => {
  const entries = [
    [ClaimKey.Subject, z.string().exactOptional()],
    [ClaimKey.ExpirationTime, z.number()],
  ] as const

  it('names a missing required key', () => {
    expect(parse(typedMap(entries, { keyLabels: ClaimKey }), new Map())).toStrictEqual([
      "Expected key 'ExpirationTime (4)' to be defined. @ 4",
    ])
  })

  it('names the key an invalid value sits under', () => {
    expect(parse(typedMap(entries, { keyLabels: ClaimKey }), new Map([[4, 'not-a-number']]))).toStrictEqual([
      'Invalid input: expected number, received string @ ExpirationTime (4)',
    ])
  })

  it('names an unexpected key when it is known to the labels', () => {
    const schema = typedMap(entries, { keyLabels: { ...ClaimKey, 9: 'Scope' }, allowAdditionalKeys: false })

    expect(
      parse(
        schema,
        new Map<unknown, unknown>([
          [4, 1],
          [9, 'x'],
        ])
      )
    ).toStrictEqual(["Unexpected key 'Scope (9)' found in map, additional keys are not allowed. @ 9"])
  })

  it('falls back to the raw label without keyLabels', () => {
    expect(parse(typedMap(entries), new Map())).toStrictEqual(["Expected key '4' to be defined. @ 4"])
  })

  it('does not mistake an enum forward mapping for a name', () => {
    // `ClaimKey.ExpirationTime` is 4, so `ClaimKey['ExpirationTime']` is a number, not a name
    const schema = typedMap([['ExpirationTime', z.number()]] as const, { keyLabels: ClaimKey })

    expect(parse(schema, new Map())).toStrictEqual(["Expected key 'ExpirationTime' to be defined. @ ExpirationTime"])
  })
})
