import { describe, expect, it } from 'vitest'
import { addPaths, addSearchParams } from '../utils'

const addUrlFixtures = [
  {
    baseUrl: 'https://example.org',
    paths: ['one', 'two'],
    expected: 'https://example.org/one/two',
  },
  {
    baseUrl: 'https://example.org/',
    paths: ['one', 'two'],
    expected: 'https://example.org/one/two',
  },
  {
    baseUrl: 'https://example.org/////',
    paths: ['one', 'two///'],
    expected: 'https://example.org/one/two',
  },
  {
    baseUrl: 'https://example.org/zero',
    paths: ['one', 'two/'],
    expected: 'https://example.org/zero/one/two',
  },
  {
    baseUrl: 'https://example.org/zero',
    paths: ['/one/', 'two/'],
    expected: 'https://example.org/zero/one/two',
  },
]

const addSearchParamsFixtures: Array<{
  baseUrl: string
  searchParams: Record<string, string>
  expected: string
}> = [
  {
    baseUrl: 'https://example.org',
    searchParams: { one: 'two' },
    expected: 'https://example.org?one=two',
  },
  {
    baseUrl: 'https://example.org?',
    searchParams: { one: 'two' },
    expected: 'https://example.org?one=two',
  },
  {
    baseUrl: 'https://example.org',
    searchParams: { foo: 'bar', baz: 'foo' },
    expected: 'https://example.org?foo=bar&baz=foo',
  },
  {
    baseUrl: 'https://example.org/fetch?tenant=a',
    searchParams: { sub: 'https://one.example.org' },
    expected: 'https://example.org/fetch?tenant=a&sub=https%3A%2F%2Fone.example.org',
  },
  {
    baseUrl: 'https://example.org/fetch?tenant=a&region=eu',
    searchParams: { foo: 'bar', baz: 'foo' },
    expected: 'https://example.org/fetch?tenant=a&region=eu&foo=bar&baz=foo',
  },
  {
    baseUrl: 'https://example.org/fetch?tenant=a&',
    searchParams: { one: 'two' },
    expected: 'https://example.org/fetch?tenant=a&one=two',
  },
  {
    baseUrl: 'https://example.org/fetch?flag',
    searchParams: { one: 'two' },
    expected: 'https://example.org/fetch?flag&one=two',
  },
  {
    baseUrl: 'https://example.org/a&b',
    searchParams: { one: 'two' },
    expected: 'https://example.org/a&b?one=two',
  },
]

describe('url parsing', () => {
  describe('append path to url', () => {
    it.each(addUrlFixtures)("should correctly turn '$baseUrl' into $expected", ({ paths, expected, baseUrl }) => {
      expect(addPaths(baseUrl, ...paths)).toBe(expected)
    })
  })

  describe('append search params to url', () => {
    it.each(addSearchParamsFixtures)(
      "should correctly turn '$baseUrl' into $expected",
      ({ searchParams, expected, baseUrl }) => {
        expect(addSearchParams(baseUrl, searchParams)).toBe(expected)
      }
    )
  })
})
