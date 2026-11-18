import { expect, suite, test } from 'vitest'
import { getJsonPathValueAndKey, zIso4217Amount, zIso4217CurrencyCode } from '../utils'

suite('getJsonPathValueAndKey', () => {
  suite('edge cases', () => {
    test('returns undefined for empty query', () => {
      expect(getJsonPathValueAndKey([], { a: 1 })).toBeUndefined()
    })

    test('returns undefined for null data', () => {
      expect(getJsonPathValueAndKey(['a'], null)).toBeUndefined()
    })

    test('returns undefined for primitive data', () => {
      expect(getJsonPathValueAndKey(['a'], 'string')).toBeUndefined()
      expect(getJsonPathValueAndKey(['a'], 123)).toBeUndefined()
      expect(getJsonPathValueAndKey(['a'], true)).toBeUndefined()
    })

    test('returns undefined when key does not exist', () => {
      expect(getJsonPathValueAndKey(['missing'], { a: 1 })).toBeUndefined()
    })
  })

  suite('simple path', () => {
    test('returns key and value for top-level key', () => {
      expect(getJsonPathValueAndKey(['a'], { a: 1 })).toEqual({ key: 'a', value: 1 })
    })

    test('returns key and value for string value', () => {
      expect(getJsonPathValueAndKey(['name'], { name: 'Alice' })).toEqual({ key: 'name', value: 'Alice' })
    })

    test('returns key and value for boolean value', () => {
      expect(getJsonPathValueAndKey(['active'], { active: false })).toEqual({ key: 'active', value: false })
    })

    test('returns key and value for null value', () => {
      expect(getJsonPathValueAndKey(['x'], { x: null })).toEqual({ key: 'x', value: null })
    })

    test('returns key and value for object value', () => {
      expect(getJsonPathValueAndKey(['a'], { a: { b: 2 } })).toEqual({ key: 'a', value: { b: 2 } })
    })
  })

  suite('nested path', () => {
    test('returns key and value for nested key', () => {
      expect(getJsonPathValueAndKey(['a', 'b'], { a: { b: 42 } })).toEqual({ key: 'b', value: 42 })
    })

    test('returns key and value for deeply nested key', () => {
      expect(getJsonPathValueAndKey(['a', 'b', 'c'], { a: { b: { c: 'deep' } } })).toEqual({ key: 'c', value: 'deep' })
    })

    test('returns undefined when intermediate key is missing', () => {
      expect(getJsonPathValueAndKey(['a', 'b'], { a: undefined })).toBeUndefined()
    })

    test('returns undefined when intermediate value is not an object', () => {
      expect(getJsonPathValueAndKey(['a', 'b'], { a: 'string' })).toBeUndefined()
    })
  })

  suite('null wildcard', () => {
    test('returns first matching child when head is null', () => {
      expect(getJsonPathValueAndKey([null, 'b'], { x: { b: 1 }, y: { b: 2 } })).toEqual({ key: 'b', value: 1 })
    })

    test('returns undefined when no child matches', () => {
      expect(getJsonPathValueAndKey([null, 'z'], { x: { b: 1 }, y: { b: 2 } })).toBeUndefined()
    })

    test('handles null as only element — returns first entry', () => {
      expect(getJsonPathValueAndKey([null], { a: 1, b: 2 })).toEqual({ key: 'a', value: 1 })
    })

    test('handles null wildcard mid-path', () => {
      expect(getJsonPathValueAndKey(['a', null, 'c'], { a: { x: { c: 99 } } })).toEqual({ key: 'c', value: 99 })
    })
  })
})

suite('zIso4217CurrencyCode', () => {
  test('accepts valid ISO4217 currency codes', () => {
    expect(zIso4217CurrencyCode.parse('USD')).toBe('USD')
    expect(zIso4217CurrencyCode.parse('EUR')).toBe('EUR')
    expect(zIso4217CurrencyCode.parse('GBP')).toBe('GBP')
    expect(zIso4217CurrencyCode.parse('JPY')).toBe('JPY')
    expect(zIso4217CurrencyCode.parse('AED')).toBe('AED')
    expect(zIso4217CurrencyCode.parse('ZWL')).toBe('ZWL')
  })

  test('rejects invalid currency codes', () => {
    expect(() => zIso4217CurrencyCode.parse('ABC')).toThrow()
    expect(() => zIso4217CurrencyCode.parse('XXX')).toThrow()
    expect(() => zIso4217CurrencyCode.parse('US')).toThrow()
    expect(() => zIso4217CurrencyCode.parse('USDD')).toThrow()
  })

  test('rejects lowercase currency codes', () => {
    expect(() => zIso4217CurrencyCode.parse('usd')).toThrow()
    expect(() => zIso4217CurrencyCode.parse('eur')).toThrow()
    expect(() => zIso4217CurrencyCode.parse('Usd')).toThrow()
  })

  test('rejects empty string', () => {
    expect(() => zIso4217CurrencyCode.parse('')).toThrow()
  })

  test('rejects non-string values', () => {
    expect(() => zIso4217CurrencyCode.parse(123)).toThrow()
    expect(() => zIso4217CurrencyCode.parse(null)).toThrow()
    expect(() => zIso4217CurrencyCode.parse(undefined)).toThrow()
  })
})

suite('zIso4217Amount', () => {
  suite('valid amounts', () => {
    test('accepts correct format with valid currency code', () => {
      expect(zIso4217Amount.parse('49.99 EUR')).toBe('49.99 EUR')
      expect(zIso4217Amount.parse('100.00 USD')).toBe('100.00 USD')
      expect(zIso4217Amount.parse('0.00 EUR')).toBe('0.00 EUR')
      expect(zIso4217Amount.parse('1234567.89 GBP')).toBe('1234567.89 GBP')
      expect(zIso4217Amount.parse('9.9 JPY')).toBe('9.9 JPY')
    })

    test('accepts amounts with multiple decimal places', () => {
      expect(zIso4217Amount.parse('1.000 KWD')).toBe('1.000 KWD')
      expect(zIso4217Amount.parse('10.5 USD')).toBe('10.5 USD')
    })

    test('accepts zero amount', () => {
      expect(zIso4217Amount.parse('0.0 USD')).toBe('0.0 USD')
    })

    test('accepts large amounts', () => {
      expect(zIso4217Amount.parse('9999999999.99 USD')).toBe('9999999999.99 USD')
    })
  })

  suite('invalid format', () => {
    test('rejects amount without decimal part', () => {
      expect(() => zIso4217Amount.parse('100 USD')).toThrow()
    })

    test('rejects amount without currency code', () => {
      expect(() => zIso4217Amount.parse('100.00')).toThrow()
    })

    test('rejects amount with wrong separator', () => {
      expect(() => zIso4217Amount.parse('100.00-USD')).toThrow()
      expect(() => zIso4217Amount.parse('100.00_USD')).toThrow()
    })

    test('rejects negative amounts', () => {
      expect(() => zIso4217Amount.parse('-100.00 USD')).toThrow()
    })

    test('rejects amount with comma decimal separator', () => {
      expect(() => zIso4217Amount.parse('100,00 USD')).toThrow()
    })

    test('rejects extra whitespace', () => {
      expect(() => zIso4217Amount.parse('100.00  USD')).toThrow()
      expect(() => zIso4217Amount.parse(' 100.00 USD')).toThrow()
      expect(() => zIso4217Amount.parse('100.00 USD ')).toThrow()
    })

    test('rejects empty string', () => {
      expect(() => zIso4217Amount.parse('')).toThrow()
    })

    test('rejects non-string values', () => {
      expect(() => zIso4217Amount.parse(100)).toThrow()
      expect(() => zIso4217Amount.parse(null)).toThrow()
      expect(() => zIso4217Amount.parse(undefined)).toThrow()
    })
  })

  suite('invalid currency code in amount', () => {
    test('rejects unknown currency codes', () => {
      expect(() => zIso4217Amount.parse('100.00 ABC')).toThrow()
      expect(() => zIso4217Amount.parse('100.00 XXX')).toThrow()
    })

    test('rejects lowercase currency codes', () => {
      expect(() => zIso4217Amount.parse('100.00 usd')).toThrow()
      expect(() => zIso4217Amount.parse('100.00 eur')).toThrow()
    })

    test('rejects 2-letter currency codes', () => {
      expect(() => zIso4217Amount.parse('100.00 US')).toThrow()
    })

    test('rejects 4-letter currency codes', () => {
      expect(() => zIso4217Amount.parse('100.00 USDD')).toThrow()
    })

    test('provides correct error message for invalid currency code', () => {
      const result = zIso4217Amount.safeParse('100.00 ABC')
      expect(result.success).toBe(false)
      if (!result.success) {
        const messages = result.error.issues.map((i) => i.message)
        expect(messages).toContain('Invalid ISO4217 currency code')
      }
    })
  })

  suite('boundary currency codes in amounts', () => {
    test('accepts first currency in list (AED)', () => {
      expect(zIso4217Amount.parse('1.00 AED')).toBe('1.00 AED')
    })

    test('accepts last currency in list (ZWL)', () => {
      expect(zIso4217Amount.parse('1.00 ZWL')).toBe('1.00 ZWL')
    })
  })
})
