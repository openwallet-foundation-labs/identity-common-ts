import { describe, expect, test } from 'vitest'
import { zDataUrl } from '../validation.js'

describe('zDataUrl', () => {
  test.each([
    ['base64 png', 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA'],
    ['base64 jpeg', 'data:image/jpeg;base64,/9j/4AAQSkZJRg'],
    ['base64 svg+xml', 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciLz4='],
  ])('accepts %s data urls', (_description, url) => {
    const result = zDataUrl.safeParse(url)
    expect(result.success).toBe(true)
  })

  test.each([
    ['a regular https url', 'https://example.com/logo.png'],
    ['a data url missing the encoding and data segment', 'data:image/png'],
    ['an empty string', ''],
  ])('rejects %s', (_description, url) => {
    const result = zDataUrl.safeParse(url)
    expect(result.success).toBe(false)
  })
})
