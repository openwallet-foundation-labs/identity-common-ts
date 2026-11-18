import { type Jwk, jwsHeaderFromSigner, signJwt } from '@owf/jose'
import { describe, expect, test, vi } from 'vitest'
import { Oauth2ServerErrorResponseError } from '../../error/Oauth2ServerErrorResponseError'
import { parseJarRequest, verifyJarRequest } from '../../jar/handle-jar-request/verify-jar-request'
import { callbacks, getSignJwsCallback } from '../util.mjs'

describe('parseJarRequest', () => {
  test.each([
    'urn:ietf:params:oauth:request_uri:abc',
    'http://169.254.169.254/latest/meta-data/',
    'file:///etc/passwd',
  ])("does not fetch non https request_uri '%s'", async (requestUri) => {
    const fetch = vi.fn()

    const error = await parseJarRequest({
      jarRequestParams: { client_id: 'x', request_uri: requestUri },
      callbacks: { fetch },
      allowRequestUri: true,
    }).catch((error) => error)

    expect(error).toBeInstanceOf(Oauth2ServerErrorResponseError)
    expect(error.errorResponse.error).toEqual('invalid_request_uri')
    expect(fetch).not.toHaveBeenCalled()
  })

  test('does not fetch request_uri by default', async () => {
    const fetch = vi.fn()

    await expect(
      parseJarRequest({
        jarRequestParams: { client_id: 'x', request_uri: 'https://attacker.example.com/request.jwt' },
        callbacks: { fetch },
      })
    ).rejects.toThrow('request_uri is not allowed')
    expect(fetch).not.toHaveBeenCalled()
  })

  test('does not fetch request_uri when allowRequestUri is false', async () => {
    const fetch = vi.fn()

    await expect(
      parseJarRequest({
        jarRequestParams: { client_id: 'x', request_uri: 'https://attacker.example.com/request.jwt' },
        callbacks: { fetch },
        allowRequestUri: false,
      })
    ).rejects.toThrow('request_uri is not allowed')
    expect(fetch).not.toHaveBeenCalled()
  })
})

describe('verifyJarRequest', () => {
  const clientJwk = {
    kty: 'EC',
    d: '6xn3gj1pQisseLDhd1qtGbBr9oWBwxxvAMBSDerbSzk',
    crv: 'P-256',
    x: 'CQHN_Jmxy4yDZzDmudBArRip9DtU8bpNDdtya7yj6f4',
    y: 'sDsPt93iLO7eZdt0-qVwD3bRAaG1V_3wmYdw3dr_lfs',
  } satisfies Jwk
  const { d: _, ...clientJwkPublic } = clientJwk
  const signer = { method: 'jwk', alg: 'ES256', publicJwk: clientJwkPublic } as const

  const now = new Date('2026-01-01T00:00:00Z')
  const nowInSeconds = 1767225600

  // A request object as `createJarAuthorizationRequest` creates it, but with the given typ
  const signRequestObject = async (typ: string) => {
    const { jwt } = await signJwt({
      header: { ...jwsHeaderFromSigner(signer), typ },
      payload: { client_id: 'wallet', iat: nowInSeconds, exp: nowInSeconds + 60 },
      signer,
      signJwsCallback: getSignJwsCallback([clientJwk]),
    })

    return jwt
  }

  const verify = async (typ: string) =>
    verifyJarRequest({
      jarRequestParams: { client_id: 'wallet' },
      authorizationRequestJwt: await signRequestObject(typ),
      callbacks: { verifyJws: callbacks.verifyJws },
      jwtSigner: signer,
      now,
    })

  test.each([
    'application/oauth-authz-req+jwt',
    'OAuth-Authz-Req+JWT',
    // The typ some existing deployments use instead
    'JWT',
  ])('verifies a request object whose typ is %s', async (typ) => {
    const { jwt } = await verify(typ)

    expect(jwt.header.typ).toEqual(typ)
  })

  test('rejects a request object whose typ is not oauth-authz-req+jwt or jwt as invalid_request_object', async () => {
    await expect(verify('dpop+jwt')).rejects.toMatchObject({
      errorResponse: {
        error: 'invalid_request_object',
        error_description:
          'Invalid Jar Request Object typ header. Expected "oauth-authz-req+jwt" or "jwt", received "dpop+jwt".',
      },
    })
  })
})
