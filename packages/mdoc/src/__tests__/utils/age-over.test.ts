import { describe, expect, test } from 'vitest'
import { findAgeOverCandidate, parseAgeOverIdentifier } from '../..'

describe('parseAgeOverIdentifier', () => {
  test.each([
    ['age_over_00', 0],
    ['age_over_08', 8],
    ['age_over_18', 18],
    ['age_over_99', 99],
  ])('parses %s', (elementIdentifier, nn) => {
    expect(parseAgeOverIdentifier(elementIdentifier)).toBe(nn)
  })

  test.each([
    'age_over_',
    'age_over_8',
    'age_over_018',
    'age_over_123',
    'age_over____18',
    'age_over_18abc',
    'age_over_123ABC',
    'age_over_+1',
    'age_over_ 18',
    'age_over_18 ',
    'age_over_1.5',
    'age_over_١٨',
    'xage_over_18',
    'age_in_years',
  ])('does not parse %s', (elementIdentifier) => {
    expect(parseAgeOverIdentifier(elementIdentifier)).toBeUndefined()
  })
})

describe('findAgeOverCandidate', () => {
  test('ignores identifiers that only look like age attestations', () => {
    const candidates = [
      { elementIdentifier: 'age_over_18abc', elementValue: true },
      { elementIdentifier: 'age_over_021', elementValue: true },
      { elementIdentifier: 'age_over_21', elementValue: true },
    ]

    expect(findAgeOverCandidate('age_over_18', candidates)?.elementIdentifier).toBe('age_over_21')
  })

  test('does not answer a malformed request', () => {
    expect(
      findAgeOverCandidate('age_over_18abc', [{ elementIdentifier: 'age_over_18', elementValue: true }])
    ).toBeUndefined()
  })
})
