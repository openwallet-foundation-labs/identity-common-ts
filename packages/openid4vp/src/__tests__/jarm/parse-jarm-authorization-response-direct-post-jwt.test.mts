import { describe, expect, test } from 'vitest'
import { parseJarmAuthorizationResponseDirectPostJwt } from '../../jarm/parse-jarm-authorization-response-direct-post-jwt'

describe('parseJarmAuthorizationResponseDirectPostJwt', () => {
  test('accepts a mixed-case form-urlencoded Content-Type', async () => {
    const response = 'a.b.c'
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
