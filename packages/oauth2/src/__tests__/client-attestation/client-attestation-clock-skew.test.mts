import * as jose from 'jose'
import { beforeAll, describe, expect, test } from 'vitest'
import { verifyPreAuthorizedCodeAccessTokenRequest } from '../../access-token/verify-access-token-request'
import { verifyPushedAuthorizationRequest } from '../../authorization-request/verify-pushed-authorization-request'
import { createClientAttestationJwt } from '../../client-attestation/client-attestation'
import { createClientAttestationPopJwt } from '../../client-attestation/client-attestation-pop'
import type { Jwk } from '../../common/jwk/z-jwk'
import type { RequestLike } from '../../common/z-common'
import { createDpopJwt } from '../../dpop/dpop'
import type { AuthorizationServerMetadata } from '../../metadata/authorization-server/z-authorization-server-metadata'
import { Oauth2AuthorizationServer } from '../../Oauth2AuthorizationServer'
import {
  authorizationCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
  refreshTokenGrantIdentifier,
} from '../../z-grant-type'
import { callbacks, getSignJwtCallback } from '../util.mjs'

const authorizationServerMetadata = {
  issuer: 'https://server.com',
  token_endpoint: 'https://server.com/token',
  pushed_authorization_request_endpoint: 'https://server.com/par',
} satisfies AuthorizationServerMetadata

// Fixed verification time so the tests never depend on the wall clock.
const now = new Date('2026-01-01T00:00:00Z')
const nowInSeconds = Math.floor(now.getTime() / 1000)

async function generateEs256Key() {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  return {
    privateJwk: (await jose.exportJWK(privateKey)) as Jwk,
    publicJwk: (await jose.exportJWK(publicKey)) as Jwk,
  }
}

describe('Client attestation clock skew', () => {
  let attester: Awaited<ReturnType<typeof generateEs256Key>>
  let instance: Awaited<ReturnType<typeof generateEs256Key>>
  let signJwt: ReturnType<typeof getSignJwtCallback>
  let clientAttestationJwt: string

  beforeAll(async () => {
    attester = await generateEs256Key()
    instance = await generateEs256Key()
    signJwt = getSignJwtCallback([attester.privateJwk, instance.privateJwk])

    clientAttestationJwt = await createClientAttestationJwt({
      callbacks: { signJwt },
      clientId: 'wallet',
      confirmation: { jwk: instance.publicJwk },
      issuedAt: now,
      expiresAt: new Date(now.getTime() + 3600 * 1000),
      signer: { method: 'jwk', alg: 'ES256', publicJwk: attester.publicJwk },
    })
  })

  // A PoP created by a wallet whose clock runs `secondsAhead` seconds ahead of the server.
  const createPopWithNbfAhead = (secondsAhead: number) =>
    createClientAttestationPopJwt({
      callbacks: { signJwt, generateRandom: callbacks.generateRandom },
      authorizationServer: authorizationServerMetadata.issuer,
      clientAttestation: clientAttestationJwt,
      issuedAt: new Date((nowInSeconds + secondsAhead) * 1000),
      additionalPayload: { nbf: nowInSeconds + secondsAhead },
    })

  const invalidClient = { status: 401, errorResponse: { error: 'invalid_client' } }

  describe('pushed authorization request', () => {
    const verify = (clientAttestationPopJwt: string, allowedSkewInSeconds?: number) =>
      verifyPushedAuthorizationRequest({
        authorizationServerMetadata,
        authorizationRequest: { client_id: 'wallet' },
        request: { headers: new Headers(), method: 'POST', url: 'https://server.com/par' },
        callbacks,
        now,
        clientAttestation: {
          required: true,
          clientAttestationJwt,
          clientAttestationPopJwt,
          allowedSkewInSeconds,
        },
      })

    test('rejects a PoP with nbf 2 seconds in the future when no skew is allowed', async () => {
      const pop = await createPopWithNbfAhead(2)
      await expect(verify(pop)).rejects.toMatchObject(invalidClient)
      await expect(verify(pop)).rejects.toThrow("jwt 'nbf' is in the future")
    })

    test('accepts a PoP with nbf 2 seconds in the future when 5 seconds of skew are allowed', async () => {
      const result = await verify(await createPopWithNbfAhead(2), 5)
      expect(result.clientAttestation?.clientAttestationPop.payload.nbf).toBe(nowInSeconds + 2)
    })

    test('rejects a PoP with nbf 10 seconds in the future when 5 seconds of skew are allowed', async () => {
      await expect(verify(await createPopWithNbfAhead(10), 5)).rejects.toMatchObject(invalidClient)
    })
  })

  describe('access token request', () => {
    const verify = (clientAttestationPopJwt: string, allowedSkewInSeconds?: number) =>
      verifyPreAuthorizedCodeAccessTokenRequest({
        authorizationServerMetadata,
        accessTokenRequest: { grant_type: preAuthorizedCodeGrantIdentifier, 'pre-authorized_code': 'code' },
        grant: { grantType: preAuthorizedCodeGrantIdentifier, preAuthorizedCode: 'code' },
        expectedPreAuthorizedCode: 'code',
        request: { headers: new Headers(), method: 'POST', url: 'https://server.com/token' },
        callbacks,
        now,
        clientAttestation: {
          required: true,
          clientAttestationJwt,
          clientAttestationPopJwt,
          allowedSkewInSeconds,
        },
      })

    test('rejects a PoP with nbf 2 seconds in the future when no skew is allowed', async () => {
      const pop = await createPopWithNbfAhead(2)
      await expect(verify(pop)).rejects.toMatchObject(invalidClient)
      await expect(verify(pop)).rejects.toThrow("jwt 'nbf' is in the future")
    })

    test('accepts a PoP with nbf 2 seconds in the future when 5 seconds of skew are allowed', async () => {
      const result = await verify(await createPopWithNbfAhead(2), 5)
      expect(result.clientAttestation?.clientAttestationPop?.payload.nbf).toBe(nowInSeconds + 2)
    })

    test('rejects a PoP with nbf 10 seconds in the future when 5 seconds of skew are allowed', async () => {
      await expect(verify(await createPopWithNbfAhead(10), 5)).rejects.toMatchObject(invalidClient)
    })
  })

  describe('access token request with DPoP-bound client attestation (attest_jwt_client_auth_dpop)', () => {
    const tokenRequest = { method: 'POST', url: 'https://server.com/token' } as const

    const verify = async (attestationNbfAhead: number, allowedSkewInSeconds?: number) => {
      const clientAttestationJwt = await createClientAttestationJwt({
        callbacks: { signJwt },
        clientId: 'wallet',
        confirmation: { jwk: instance.publicJwk },
        issuedAt: now,
        expiresAt: new Date(now.getTime() + 3600 * 1000),
        signer: { method: 'jwk', alg: 'ES256', publicJwk: attester.publicJwk },
        additionalPayload: { nbf: nowInSeconds + attestationNbfAhead },
      })
      const dpopJwt = await createDpopJwt({
        callbacks: { ...callbacks, signJwt },
        request: tokenRequest,
        issuedAt: now,
        signer: { method: 'jwk', alg: 'ES256', publicJwk: instance.publicJwk },
      })

      return verifyPreAuthorizedCodeAccessTokenRequest({
        authorizationServerMetadata,
        accessTokenRequest: { grant_type: preAuthorizedCodeGrantIdentifier, 'pre-authorized_code': 'code' },
        grant: { grantType: preAuthorizedCodeGrantIdentifier, preAuthorizedCode: 'code' },
        expectedPreAuthorizedCode: 'code',
        request: { ...tokenRequest, headers: new Headers({ DPoP: dpopJwt }) },
        callbacks,
        now,
        dpop: { required: true, jwt: dpopJwt, allowedSigningAlgs: ['ES256'] },
        clientAttestation: { required: true, clientAttestationJwt, allowedSkewInSeconds },
      })
    }

    test('rejects an attestation with nbf 2 seconds in the future when no skew is allowed', async () => {
      await expect(verify(2)).rejects.toMatchObject(invalidClient)
    })

    test('accepts an attestation with nbf 2 seconds in the future when 5 seconds of skew are allowed', async () => {
      const result = await verify(2, 5)
      expect(result.clientAttestation?.clientAttestation.payload.nbf).toBe(nowInSeconds + 2)
    })

    test('rejects an attestation with nbf 10 seconds in the future when 5 seconds of skew are allowed', async () => {
      await expect(verify(10, 5)).rejects.toMatchObject(invalidClient)
    })
  })

  describe('Oauth2AuthorizationServer clock skew default', () => {
    const createAuthorizationServer = () =>
      new Oauth2AuthorizationServer({
        callbacks: { ...callbacks, signJwt },
        allowedSkewInSeconds: 5,
      })

    interface RequestVerificationOptions {
      request: RequestLike
      now: Date
      dpop: { required: true; jwt: string; maxProofAgeSeconds: number; allowedSkewInSeconds?: number }
      clientAttestation: {
        required: true
        clientAttestationJwt: string
        clientAttestationPopJwt: string
        allowedSkewInSeconds?: number
      }
    }

    const requestVerifiers: Array<{
      method: string
      url: string
      verify: (options: RequestVerificationOptions) => Promise<unknown>
    }> = [
      {
        method: 'verifyPushedAuthorizationRequest',
        url: 'https://server.com/par',
        verify: (options) =>
          createAuthorizationServer().verifyPushedAuthorizationRequest({
            ...options,
            authorizationServerMetadata,
            authorizationRequest: { client_id: 'wallet' },
          }),
      },
      {
        method: 'verifyAuthorizationChallengeRequest',
        url: 'https://server.com/authorize-challenge',
        verify: (options) =>
          createAuthorizationServer().verifyAuthorizationChallengeRequest({
            ...options,
            authorizationServerMetadata,
            authorizationChallengeRequest: { client_id: 'wallet' },
          }),
      },
      {
        method: 'verifyPreAuthorizedCodeAccessTokenRequest',
        url: 'https://server.com/token',
        verify: (options) =>
          createAuthorizationServer().verifyPreAuthorizedCodeAccessTokenRequest({
            ...options,
            authorizationServerMetadata,
            accessTokenRequest: { grant_type: preAuthorizedCodeGrantIdentifier, 'pre-authorized_code': 'code' },
            grant: { grantType: preAuthorizedCodeGrantIdentifier, preAuthorizedCode: 'code' },
            expectedPreAuthorizedCode: 'code',
          }),
      },
      {
        method: 'verifyAuthorizationCodeAccessTokenRequest',
        url: 'https://server.com/token',
        verify: (options) =>
          createAuthorizationServer().verifyAuthorizationCodeAccessTokenRequest({
            ...options,
            authorizationServerMetadata,
            accessTokenRequest: { grant_type: authorizationCodeGrantIdentifier, code: 'code' },
            grant: { grantType: authorizationCodeGrantIdentifier, code: 'code' },
            expectedCode: 'code',
          }),
      },
      {
        method: 'verifyRefreshTokenAccessTokenRequest',
        url: 'https://server.com/token',
        verify: (options) =>
          createAuthorizationServer().verifyRefreshTokenAccessTokenRequest({
            ...options,
            authorizationServerMetadata,
            accessTokenRequest: { grant_type: refreshTokenGrantIdentifier, refresh_token: 'refresh' },
            grant: { grantType: refreshTokenGrantIdentifier, refreshToken: 'refresh' },
            expectedRefreshToken: 'refresh',
          }),
      },
    ]

    describe.each(requestVerifiers)('$method', ({ url, verify }) => {
      // DPoP proof and client attestation PoP from a wallet whose clock runs 2 seconds ahead of the server.
      const createOptions = async (): Promise<RequestVerificationOptions> => {
        const request = { headers: new Headers(), method: 'POST', url } as const
        const dpopJwt = await createDpopJwt({
          callbacks: { ...callbacks, signJwt },
          request,
          issuedAt: new Date((nowInSeconds + 2) * 1000),
          signer: { method: 'jwk', alg: 'ES256', publicJwk: instance.publicJwk },
        })

        return {
          request,
          now,
          dpop: { required: true, jwt: dpopJwt, maxProofAgeSeconds: 60 },
          clientAttestation: {
            required: true,
            clientAttestationJwt,
            clientAttestationPopJwt: await createPopWithNbfAhead(2),
          },
        }
      }

      test('applies the server default to DPoP and client attestation verification', async () => {
        await expect(verify(await createOptions())).resolves.toMatchObject({
          dpop: { jwkThumbprint: expect.any(String) },
          clientAttestation: { clientAttestationPop: { payload: { nbf: nowInSeconds + 2 } } },
        })
      })

      test('a per-call DPoP skew of 0 overrides the server default', async () => {
        const options = await createOptions()
        await expect(verify({ ...options, dpop: { ...options.dpop, allowedSkewInSeconds: 0 } })).rejects.toMatchObject({
          errorResponse: { error: 'invalid_dpop_proof' },
        })
      })

      test('a per-call client attestation skew of 0 overrides the server default', async () => {
        const options = await createOptions()
        await expect(
          verify({ ...options, clientAttestation: { ...options.clientAttestation, allowedSkewInSeconds: 0 } })
        ).rejects.toMatchObject(invalidClient)
      })
    })

    test('applies its default to direct client attestation verification and allows an override', async () => {
      const clientAttestationPopJwt = await createPopWithNbfAhead(2)
      const options = {
        authorizationServer: authorizationServerMetadata.issuer,
        clientAttestationJwt,
        clientAttestationPopJwt,
        now,
      }

      const result = await createAuthorizationServer().verifyClientAttestation(options)
      expect(result.clientAttestationPop.payload.nbf).toBe(nowInSeconds + 2)

      await expect(
        createAuthorizationServer().verifyClientAttestation({
          ...options,
          allowedSkewInSeconds: 0,
        })
      ).rejects.toMatchObject(invalidClient)
    })

    test('applies its default to direct DPoP verification and allows an override', async () => {
      const request = { headers: new Headers(), method: 'POST', url: 'https://server.com/token' } as const
      const dpopJwt = await createDpopJwt({
        callbacks: { ...callbacks, signJwt },
        request,
        issuedAt: new Date((nowInSeconds + 2) * 1000),
        signer: { method: 'jwk', alg: 'ES256', publicJwk: instance.publicJwk },
      })
      const options = {
        dpopJwt,
        request,
        now,
        maxProofAgeSeconds: 60,
      }

      const result = await createAuthorizationServer().verifyDpopJwt(options)
      expect(result.payload.iat).toBe(nowInSeconds + 2)

      await expect(
        createAuthorizationServer().verifyDpopJwt({
          ...options,
          allowedSkewInSeconds: 0,
        })
      ).rejects.toMatchObject({ errorResponse: { error: 'invalid_dpop_proof' } })
    })
  })
})
