import { describe, expect, test } from 'vitest'
import { isJwtTyp, zDataUrl, zTyp } from '../validation.js'

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

describe('zTyp', () => {
  const zProofTyp = zTyp('openid4vci-proof+jwt')

  test.each([
    ['the short form', 'openid4vci-proof+jwt'],
    ['the full media type', 'application/openid4vci-proof+jwt'],
    ['the short form in different casing', 'OpenID4VCI-Proof+JWT'],
    ['the full media type in different casing', 'Application/OpenID4VCI-Proof+JWT'],
  ])('accepts %s and keeps the value as sent', (_description, typ) => {
    expect(zProofTyp.parse(typ)).toEqual(typ)
  })

  test.each([
    ['a different typ', 'jwt'],
    ['a different media type prefix', 'text/openid4vci-proof+jwt'],
    ['an empty string', ''],
    ['a non-string value', 1],
    ['undefined', undefined],
  ])('rejects %s', (_description, typ) => {
    expect(zProofTyp.safeParse(typ).success).toBe(false)
  })
})

describe('isJwtTyp', () => {
  test.each([
    ['the short form', 'openid4vci-proof+jwt'],
    ['the full media type', 'application/openid4vci-proof+jwt'],
    ['the short form in different casing', 'OpenID4VCI-Proof+JWT'],
    ['the full media type in different casing', 'Application/OpenID4VCI-Proof+JWT'],
  ])('matches %s', (_description, value) => {
    expect(isJwtTyp(value, 'openid4vci-proof+jwt')).toBe(true)
  })

  test.each([
    ['a different typ', 'jwt'],
    ['a different media type prefix', 'text/openid4vci-proof+jwt'],
    ['an empty string', ''],
    ['a non-string value', 1],
    ['undefined', undefined],
  ])('does not match %s', (_description, value) => {
    expect(isJwtTyp(value, 'openid4vci-proof+jwt')).toBe(false)
  })
})
