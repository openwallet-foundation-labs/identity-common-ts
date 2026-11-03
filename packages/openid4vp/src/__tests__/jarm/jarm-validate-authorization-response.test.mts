import { Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { describe, expect, test } from 'vitest'
import { jarmAuthorizationResponseValidate } from '../../jarm/jarm-authorization-response/jarm-validate-authorization-response.js'

const now = new Date('2026-01-01T00:00:00.000Z')
const seconds = (date: Date) => Math.floor(date.getTime() / 1000)
const response = (exp: number, aud = 'client') => ({ iss: 'https://wallet.example', aud, exp })

describe('jarmAuthorizationResponseValidate', () => {
  test('verifies exp at the given now, with the given skew', () => {
    const expiredAMinuteAgo = response(seconds(now) - 60)

    expect(() =>
      jarmAuthorizationResponseValidate({ expectedClientId: 'client', authorizationResponse: expiredAMinuteAgo, now })
    ).toThrow(
      expect.objectContaining({
        errorResponse: expect.objectContaining({ error_description: 'The JARM authorization response is expired.' }),
      })
    )

    expect(() =>
      jarmAuthorizationResponseValidate({
        expectedClientId: 'client',
        authorizationResponse: expiredAMinuteAgo,
        now,
        allowedSkewInSeconds: 120,
      })
    ).not.toThrow()
  })

  test('rejects a response for another client', () => {
    expect(() =>
      jarmAuthorizationResponseValidate({
        expectedClientId: 'client',
        authorizationResponse: response(seconds(now) + 60, 'other-client'),
        now,
      })
    ).toThrow(
      expect.objectContaining({
        constructor: Oauth2ServerErrorResponseError,
        errorResponse: expect.objectContaining({
          error_description: "Invalid 'aud' claim in the JARM authorization response.",
        }),
      })
    )
  })
})
