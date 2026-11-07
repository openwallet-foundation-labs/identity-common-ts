import { Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { JoseSignatureVerificationError, JoseValidationError, type Jwk, signJwt } from '@owf/jose'
import * as jose from 'jose'
import { describe, expect, test } from 'vitest'
import { callbacks, getSignJwsCallback } from '../../../../oauth2/src/__tests__/util.mjs'
import { verifyJarmAuthorizationResponse } from '../../jarm/jarm-authorization-response/verify-jarm-authorization-response.js'

const now = new Date('2026-01-01T00:00:00.000Z')
const seconds = (date: Date) => Math.floor(date.getTime() / 1000)

const authorizationRequestPayload = {
  client_id: 'verifier',
  response_type: 'vp_token',
  response_mode: 'direct_post.jwt',
  response_uri: 'https://verifier.example/response',
  nonce: 'nonce',
} as const

const generateKeyPair = async () => {
  const { privateKey, publicKey } = await jose.generateKeyPair('ES256', { extractable: true })
  return { privateJwk: (await jose.exportJWK(privateKey)) as Jwk, publicJwk: (await jose.exportJWK(publicKey)) as Jwk }
}

const createResponse = async (header: Record<string, unknown>, signedBy: Awaited<ReturnType<typeof generateKeyPair>>) =>
  (
    await signJwt({
      header,
      payload: { iss: 'https://wallet.example', aud: 'verifier', exp: seconds(now) + 60, vp_token: { pid: ['vp'] } },
      signer: { method: 'jwk', alg: 'ES256', publicJwk: signedBy.publicJwk },
      signJwsCallback: getSignJwsCallback([signedBy.privateJwk]),
    })
  ).jwt

const verify = (jarmAuthorizationResponseJwt: string) =>
  verifyJarmAuthorizationResponse({
    jarmAuthorizationResponseJwt,
    authorizationRequestPayload,
    expectedClientId: 'verifier',
    callbacks,
    now,
  })

// JARM Section 2.4: the signing key is identified by the header of the response
describe('verifyJarmAuthorizationResponse with a signed response', () => {
  test('rejects a response whose header has no kid, jwk or x5c', async () => {
    const wallet = await generateKeyPair()

    await expect(verify(await createResponse({}, wallet))).rejects.toBeInstanceOf(JoseValidationError)
  })

  test('keeps the jose error as cause when the signature does not verify', async () => {
    const [wallet, other] = await Promise.all([generateKeyPair(), generateKeyPair()])

    await expect(verify(await createResponse({ jwk: wallet.publicJwk }, wallet))).resolves.toMatchObject({
      issuer: 'https://wallet.example',
    })

    const [header, payload] = (await createResponse({ jwk: wallet.publicJwk }, wallet)).split('.')
    const [, , otherSignature] = (await createResponse({ jwk: other.publicJwk }, other)).split('.')
    const error = await verify(`${header}.${payload}.${otherSignature}`).catch((error) => error)
    expect(error).toBeInstanceOf(Oauth2ServerErrorResponseError)
    expect(error.errorResponse.error_description).toBe('The signature of the JARM authorization response is not valid.')
    expect(error.cause).toBeInstanceOf(JoseSignatureVerificationError)
  })
})
