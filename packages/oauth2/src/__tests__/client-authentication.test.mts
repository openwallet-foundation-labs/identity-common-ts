import { Headers } from '@openid4vc/utils'
import { describe, expect, test } from 'vitest'
import {
  type ClientAuthenticationCallbackOptions,
  clientAuthenticationClientSecretBasic,
} from '../client-authentication'

describe('clientAuthenticationClientSecretBasic', () => {
  test('encodes the credentials as base64 with padding (RFC 7617 section 2)', async () => {
    const headers = new Headers()
    // 'a:~~' is 'YTp+fg==' in base64, and 'YTp-fg' in base64url
    await clientAuthenticationClientSecretBasic({ clientId: 'a', clientSecret: '~~' })({
      headers,
    } as unknown as ClientAuthenticationCallbackOptions)

    expect(headers.get('Authorization')).toBe('Basic YTp+fg==')
  })

  test('form-urlencodes the client id and secret before joining them (RFC 6749 section 2.3.1)', async () => {
    const headers = new Headers()
    await clientAuthenticationClientSecretBasic({ clientId: 'urn:client:1', clientSecret: 'a b+c%' })({
      headers,
    } as unknown as ClientAuthenticationCallbackOptions)

    const credentials = atob(headers.get('Authorization')?.replace('Basic ', '') ?? '')
    expect(credentials).toBe('urn%3Aclient%3A1:a%20b%2Bc%25')
  })
})
