import { Headers } from '@openid4vc/utils'
import { describe, expect, test } from 'vitest'
import {
  type ClientAuthenticationCallbackOptions,
  clientAuthenticationClientSecretBasic,
} from '../client-authentication'

async function basicCredentials(clientId: string, clientSecret: string) {
  const headers = new Headers()
  await clientAuthenticationClientSecretBasic({ clientId, clientSecret })({
    headers,
  } as unknown as ClientAuthenticationCallbackOptions)

  return headers.get('Authorization')
}

describe('clientAuthenticationClientSecretBasic', () => {
  test('encodes the credentials as base64 with padding (RFC 7617 Section 2)', async () => {
    // Lengths that are not a multiple of three are padded. base64url without padding gives 'YWI6Yw' and 'YWI6Y2Q'
    expect(await basicCredentials('ab', 'c')).toBe('Basic YWI6Yw==')
    expect(await basicCredentials('ab', 'cd')).toBe('Basic YWI6Y2Q=')
  })

  test('form-urlencodes the client id and secret before joining them (RFC 6749 Section 2.3.1)', async () => {
    // The example value of RFC 6749 Appendix B: SPACE, PERCENT SIGN, AMPERSAND, PLUS SIGN, POUND SIGN, EURO SIGN
    const credentials = await basicCredentials('urn:client:1', ' %&+£€')

    expect(atob(credentials?.replace('Basic ', '') ?? '')).toBe('urn%3Aclient%3A1:+%25%26%2B%C2%A3%E2%82%AC')

    // A colon in the secret is encoded as well, so the first colon always separates the id from the secret
    expect(await basicCredentials('client', 'a:b c é')).toBe(`Basic ${btoa('client:a%3Ab+c+%C3%A9')}`)
  })

  test('encodes a secret that is different in base64 and base64url', async () => {
    // 'a:~?>' is 'YTp+Pz4=' in base64 and 'YTp-Pz4' in base64url. Form-urlencoding it first leaves only characters
    // that are the same in both alphabets.
    const credentials = await basicCredentials('a', "~?>!'()*-._")

    expect(credentials).toBe(`Basic ${btoa('a:%7E%3F%3E%21%27%28%29*-._')}`)
    expect(credentials).toMatch(/^Basic [A-Za-z0-9]+={0,2}$/)
  })
})
