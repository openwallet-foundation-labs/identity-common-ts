import { CommonMediaTypes, isMediaType } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'

describe('content-type helpers', () => {
  test.each(['application/json-seq', 'multipart/related; type="application/json"'])(
    'rejects a lookalike Content-Type: %s',
    (value) => {
      const response = new Response('', { headers: { 'Content-Type': value } })
      expect(isMediaType(value, CommonMediaTypes.Json)).toBe(false)
      expect(isMediaType(response.headers.get('Content-Type'), CommonMediaTypes.Json)).toBe(false)
    }
  )

  test.each(['application/json; charset=UTF-8', 'Application/JSON'])('accepts a matching Content-Type: %s', (value) => {
    const response = new Response('', { headers: { 'Content-Type': value } })
    expect(isMediaType(value, CommonMediaTypes.Json)).toBe(true)
    expect(isMediaType(response.headers.get('Content-Type'), CommonMediaTypes.Json)).toBe(true)
  })
})
