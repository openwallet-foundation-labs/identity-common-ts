import { describe, expect, it } from 'vitest'
import z from 'zod'
import {
  formatZodError,
  IdentityError,
  parseWithErrorHandling,
  parseWithZod,
  ValidationError,
  zNumericDate,
  zodErrorMap,
} from '../index'

const zPerson = z.object({ name: z.string(), age: z.number() })
const invalidPerson = () => zPerson.safeParse({ name: 1 }, { error: zodErrorMap }).error as z.ZodError

describe('ValidationError', () => {
  it('can be caught as an IdentityError and as an Error', () => {
    const error = new ValidationError('Invalid person', invalidPerson())

    expect(error).toBeInstanceOf(ValidationError)
    expect(error).toBeInstanceOf(IdentityError)
    expect(error).toBeInstanceOf(Error)
  })

  it('is named ValidationError', () => {
    expect(new ValidationError('Invalid person', invalidPerson()).name).toBe('ValidationError')
  })

  it('appends every issue to the message, each on a line of its own', () => {
    expect(new ValidationError('Invalid person', invalidPerson()).message).toBe(
      'Invalid person\n✖ Expected string, received number at "name"\n✖ Expected number, received undefined at "age"'
    )
  })

  it('uses the message as it is when there is no zod error', () => {
    expect(new ValidationError('Invalid person').message).toBe('Invalid person')
  })

  it('carries the zod issues as details', () => {
    const zodError = invalidPerson()

    expect(new ValidationError('Invalid person', zodError).details).toBe(zodError.issues)
  })

  it('keeps the zod error on a property that is not enumerable', () => {
    const zodError = invalidPerson()

    expect(Object.getOwnPropertyDescriptor(new ValidationError('Invalid person', zodError), 'zodError')).toMatchObject({
      value: zodError,
      enumerable: false,
      writable: false,
    })
  })

  it('reports its name, message and issues in the full message', () => {
    const zodError = z.object({ name: z.string() }).safeParse({}, { error: zodErrorMap }).error as z.ZodError

    expect(new ValidationError('Invalid person', zodError).getFullMessage()).toBe(
      'ValidationError: Invalid person\n✖ Expected string, received undefined at "name" - [{"expected":"string","code":"invalid_type","path":["name"],"message":"expected string, received undefined"}]'
    )
  })
})

describe('formatZodError', () => {
  it('returns an empty string when there is no error', () => {
    expect(formatZodError(undefined)).toBe('')
  })

  it('puts every issue on a line of its own, naming its path', () => {
    expect(formatZodError(invalidPerson())).toBe(
      '✖ Expected string, received number at "name"\n✖ Expected number, received undefined at "age"'
    )
  })

  it('puts the issue of every member of a union on a line of its own', () => {
    const result = z.object({ a: z.union([z.string(), z.number()]) }).safeParse({ a: true }, { error: zodErrorMap })

    expect(formatZodError(result.error)).toBe(
      '✖ Expected string, received boolean at "a"\n    OR ✖ Expected number, received boolean at "a"'
    )
  })

  it('names the path of a nested issue with dots and array indices', () => {
    const result = z
      .object({ a: z.object({ b: z.array(z.string()) }) })
      .safeParse({ a: { b: ['x', 1] } }, { error: zodErrorMap })

    expect(formatZodError(result.error)).toBe('✖ Expected string, received number at "a.b[1]"')
  })
})

describe('parseWithErrorHandling', () => {
  it('returns the parsed data', () => {
    expect(
      parseWithErrorHandling(
        z.string().transform((value) => value.length),
        'abc'
      )
    ).toBe(3)
  })

  it('throws a ValidationError when the data does not match the schema', () => {
    expect(() => parseWithErrorHandling(zPerson, { name: 1 })).toThrow(ValidationError)
  })

  it('reports a default message followed by the issues', () => {
    expect(() => parseWithErrorHandling(zPerson, { name: 'Ada' })).toThrow(
      'Error validating structure\n✖ Expected number, received undefined at "age"'
    )
  })

  it('reports the message it is given followed by the issues', () => {
    expect(() => parseWithErrorHandling(zPerson, { name: 'Ada' }, 'Invalid person')).toThrow(
      'Invalid person\n✖ Expected number, received undefined at "age"'
    )
  })

  it('carries the issues as details', () => {
    expect(() => parseWithErrorHandling(zPerson, { name: 'Ada' })).toThrow(
      expect.objectContaining({
        details: [
          { code: 'invalid_type', expected: 'number', path: ['age'], message: 'expected number, received undefined' },
        ],
      })
    )
  })

  it.each([
    ['a number', z.number()],
    ['an enum', z.enum(['a', 'b'])],
    ['a literal', z.literal('a')],
    ['a url', z.url()],
    ['a pattern', z.string().regex(/^a/)],
    ['a maximum length', z.string().max(3)],
  ])('leaves the value out of the message when it is not %s', (_, schema) => {
    expect(() => parseWithErrorHandling(z.object({ secret: schema }), { secret: 'hunter2' })).toThrow(
      expect.objectContaining({ message: expect.not.stringContaining('hunter2') })
    )
  })
})

describe('parseWithZod', () => {
  it('returns the parsed data on success', () => {
    expect(
      parseWithZod(
        z.string().transform((value) => value.length),
        'abc',
        'Invalid value'
      )
    ).toEqual({
      success: true,
      data: 3,
    })
  })

  it('returns the formatted message, the issues and the zod error on failure rather than throwing', () => {
    const result = parseWithZod(z.object({ a: z.string() }), { a: 1 }, 'Invalid value')

    expect(result).toEqual({
      success: false,
      failure: {
        message: 'Invalid value\n✖ Expected string, received number at "a"',
        issues: [
          { code: 'invalid_type', expected: 'string', path: ['a'], message: 'expected string, received number' },
        ],
        error: expect.any(z.ZodError),
      },
    })
  })
})

describe('zodErrorMap', () => {
  it('words an issue for the parse it is passed to', () => {
    expect(z.number().safeParse('1', { error: zodErrorMap }).error?.issues[0].message).toBe(
      'expected number, received string'
    )
  })

  it('is not installed globally, so an application keeps the messages of zod itself', () => {
    expect(z.string().safeParse(1).error?.issues[0].message).toBe('Invalid input: expected string, received number')
  })
})

describe('zNumericDate', () => {
  it.each([
    ['the epoch', 0],
    ['a date before the epoch', -1],
    ['a fraction of a second', 1_700_000_000.5],
    ['a date in seconds', 1_700_000_000],
  ])('accepts %s', (_, value) => {
    expect(zNumericDate.parse(value)).toBe(value)
  })

  it.each([
    ['a numeric string', '1700000000'],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
    ['null', null],
    ['a Date', new Date(0)],
  ])('rejects %s', (_, value) => {
    expect(zNumericDate.safeParse(value).success).toBe(false)
  })
})
