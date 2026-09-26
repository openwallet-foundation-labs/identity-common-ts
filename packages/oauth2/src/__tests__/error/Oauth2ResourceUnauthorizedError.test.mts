import { describe, expect, test } from 'vitest'
import { SupportedAuthenticationScheme } from '../../access-token/verify-access-token'
import { Oauth2ErrorCodes } from '../../common/z-oauth2-error'
import { Oauth2ResourceUnauthorizedError } from '../../error/Oauth2ResourceUnauthorizedError'

describe('Oauth2ResourceUnauthorizedError', () => {
  describe('toHeaderValue', () => {
    test('omits absent parameters instead of emitting bare parameter names', () => {
      const error = new Oauth2ResourceUnauthorizedError('No Authorization header provided in request.', [
        { scheme: SupportedAuthenticationScheme.Bearer },
        { scheme: SupportedAuthenticationScheme.DPoP },
      ])

      expect(error.toHeaderValue()).toEqual('Bearer, DPoP')
    })

    test('includes only the parameters that are set', () => {
      const error = new Oauth2ResourceUnauthorizedError('Invalid token.', [
        { scheme: SupportedAuthenticationScheme.Bearer, error: Oauth2ErrorCodes.InvalidToken },
        {
          scheme: SupportedAuthenticationScheme.DPoP,
          error: Oauth2ErrorCodes.InvalidToken,
          error_description: 'Token expired',
          additionalPayload: { algs: 'ES256' },
        },
      ])

      expect(error.toHeaderValue()).toEqual(
        'Bearer error="invalid_token", DPoP error="invalid_token", error_description="Token expired", algs="ES256"'
      )
    })

    test('round-trips through fromHeaderValue', () => {
      const headerValue = 'Bearer error="invalid_token", scope="openid", DPoP error="invalid_token"'

      expect(Oauth2ResourceUnauthorizedError.fromHeaderValue(headerValue).toHeaderValue()).toEqual(headerValue)
    })
  })
})
