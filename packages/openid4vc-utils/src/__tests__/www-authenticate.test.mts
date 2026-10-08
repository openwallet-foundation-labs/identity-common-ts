import { describe, expect, test } from 'vitest'
import { encodeWwwAuthenticateHeader, parseWwwAuthenticateHeader } from '../www-authenticate.js'

describe('WWW-Authenticate Header', () => {
  test('Correctly parses single scheme', () => {
    expect(
      parseWwwAuthenticateHeader('Custom foo=bar,foo=fuzz,buzz="quoted \\"value!\\"", Bearer="true", name, age')
    ).toEqual([
      {
        payload: {
          Bearer: 'true',
          buzz: 'quoted "value!"',
          foo: ['bar', 'fuzz'],
          name: null,
          age: null,
        },
        scheme: 'Custom',
      },
    ])
  })

  test('Correctly parses multiple schemes with well-known scheme names', () => {
    expect(
      parseWwwAuthenticateHeader(
        'Custom foo=bar,foo=fuzz,buzz="quoted \\"value!\\"", Bearer="true", name, age, Bearer, Basic name="Timo", DPoP name="Timo", DPoP name="again", Bearer'
      )
    ).toEqual([
      {
        payload: {
          Bearer: 'true',
          buzz: 'quoted "value!"',
          foo: ['bar', 'fuzz'],
          name: null,
          age: null,
        },
        scheme: 'Custom',
      },
      {
        payload: {},
        scheme: 'Bearer',
      },
      {
        payload: {
          name: 'Timo',
        },
        scheme: 'Basic',
      },
      {
        payload: {
          name: 'Timo',
        },
        scheme: 'DPoP',
      },
      {
        payload: {
          name: 'again',
        },
        scheme: 'DPoP',
      },
      {
        payload: {},
        scheme: 'Bearer',
      },
    ])
  })

  test('Correctly encodes multiple schemes', () => {
    expect(
      encodeWwwAuthenticateHeader([
        {
          payload: {
            Bearer: 'true',
            buzz: 'quoted "value!"',
            foo: ['bar', 'fuzz'],
            name: null,
            age: null,
          },
          scheme: 'Custom',
        },
        {
          payload: {},
          scheme: 'Bearer',
        },
        {
          payload: {
            name: 'Timo',
          },
          scheme: 'Basic',
        },
        {
          payload: {
            name: 'Timo',
          },
          scheme: 'DPoP',
        },
        {
          payload: {
            name: 'again',
          },
          scheme: 'DPoP',
        },
        {
          payload: {},
          scheme: 'Bearer',
        },
      ])
    ).toEqual(
      'Custom Bearer="true", buzz="quoted \\"value!\\"", foo="bar", foo="fuzz", name, age, Bearer, Basic name="Timo", DPoP name="Timo", DPoP name="again", Bearer'
    )
  })

  test('Omits undefined values but keeps null values when encoding', () => {
    expect(
      encodeWwwAuthenticateHeader([
        { scheme: 'Bearer', payload: { error: undefined, scope: 'openid', name: null } },
        { scheme: 'DPoP', payload: { error: undefined, error_description: undefined } },
      ])
    ).toEqual('Bearer scope="openid", name, DPoP')
  })
})

// The values regularly hold an error message, which can carry line breaks and input from whoever
// sent the request, such as a header parameter of a token that does not verify
describe('encodeWwwAuthenticateHeader with values a header cannot carry', () => {
  const withDescription = (error_description: string) =>
    encodeWwwAuthenticateHeader([{ scheme: 'Bearer', payload: { error: 'invalid_token', error_description } }])

  test('replaces a CR LF, so that a value cannot start another header', () => {
    expect(withDescription("The 'crit' header parameter lists 'x\r\nSet-Cookie: a=b'")).toBe(
      `Bearer error="invalid_token", error_description="The 'crit' header parameter lists 'x Set-Cookie: a=b'"`
    )
  })

  test('replaces a line feed', () => {
    expect(withDescription('Invalid DPoP proof\n{\n  "error": "invalid_dpop_proof"\n}')).toBe(
      'Bearer error="invalid_token", error_description="Invalid DPoP proof {   \\"error\\": \\"invalid_dpop_proof\\" }"'
    )
  })

  test('replaces NUL, tab, DEL and other control characters', () => {
    expect(withDescription('a\u0000b\tc\u007Fd\u001Be\u0085f')).toBe(
      'Bearer error="invalid_token", error_description="a b c d e f"'
    )
  })

  test('replaces characters outside ASCII, each run of them with one space', () => {
    expect(withDescription('Jöhn-🦋-€€-x')).toBe('Bearer error="invalid_token", error_description="J hn- - -x"')
  })

  test('produces a value that Headers accepts', () => {
    const value = withDescription("kid 'x\r\nSet-Cookie: a=b\u0000' of Jöhn 🦋 not found\u2028")
    const headers = new Headers()

    headers.set('WWW-Authenticate', value)

    expect(headers.get('WWW-Authenticate')).toBe(
      `Bearer error="invalid_token", error_description="kid 'x Set-Cookie: a=b ' of J hn   not found "`
    )
  })

  test('escapes a backslash and a double quote', () => {
    expect(withDescription('expected "at+jwt" in C:\\tokens')).toBe(
      'Bearer error="invalid_token", error_description="expected \\"at+jwt\\" in C:\\\\tokens"'
    )
  })

  test('replaces characters a header cannot carry in a parameter name and a scheme', () => {
    expect(encodeWwwAuthenticateHeader([{ scheme: 'Bearer\r\nX', payload: { 'x\r\ny': 'z' } }])).toBe(
      'Bearer X x y="z"'
    )
  })

  test('cuts off an error_description longer than 500 characters', () => {
    expect(withDescription('a'.repeat(1000))).toBe(
      `Bearer error="invalid_token", error_description="${'a'.repeat(497)}..."`
    )
  })

  test('leaves an error_description of 500 characters as it is', () => {
    expect(withDescription('a'.repeat(500))).toBe(
      `Bearer error="invalid_token", error_description="${'a'.repeat(500)}"`
    )
  })

  test('cuts off an error_description before escaping it, so the quoted string stays closed', () => {
    expect(withDescription(`${'a'.repeat(496)}"${'b'.repeat(100)}`)).toBe(
      `Bearer error="invalid_token", error_description="${'a'.repeat(496)}\\"..."`
    )
  })

  test('does not cut off any other parameter', () => {
    const scope = Array.from({ length: 100 }, (_, i) => `scope-${i}`).join(' ')

    expect(encodeWwwAuthenticateHeader([{ scheme: 'Bearer', payload: { scope } }])).toBe(`Bearer scope="${scope}"`)
  })
})

describe('parseWwwAuthenticateHeader with quoted strings', () => {
  test('removes the backslash of every escaped character', () => {
    expect(parseWwwAuthenticateHeader('Bearer error_description="expected \\"at+jwt\\" in C:\\\\tokens"')).toEqual([
      { scheme: 'Bearer', payload: { error_description: 'expected "at+jwt" in C:\\tokens' } },
    ])
  })

  test('reads back a value with a backslash and a double quote as it was encoded', () => {
    const challenges = [{ scheme: 'Bearer', payload: { error_description: 'a "quoted" \\ value \\\\' } }]

    expect(parseWwwAuthenticateHeader(encodeWwwAuthenticateHeader(challenges))).toEqual(challenges)
  })
})
