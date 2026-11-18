import { base64url, stringToBytes } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { parseJarmAuthorizationResponseDirectPostJwt } from '../../jarm/parse-jarm-authorization-response-direct-post-jwt'

describe('parseJarmAuthorizationResponseDirectPostJwt', () => {
  test('accepts a mixed-case form-urlencoded Content-Type', async () => {
    const encode = (value: object) => base64url.encode(stringToBytes(JSON.stringify(value)))
    const response = `${encode({ alg: 'ES256' })}.${encode({ iss: 'https://example.com' })}.c2lnbmF0dXJl`
    const request = new Request('https://example.com', {
      method: 'POST',
      headers: { 'Content-Type': 'Application/X-WWW-Form-Urlencoded' },
      body: `response=${response}`,
    })

    await expect(parseJarmAuthorizationResponseDirectPostJwt(request)).resolves.toEqual({
      jarmAuthorizationResponseJwt: response,
    })
  })
})
