import type { VerifyJwsCallback } from '@openid4vc/oauth2'
import { isJwtTyp } from '@owf/identity-common'
import { JoseInvalidArgumentError, type Jwk, signJwt } from '@owf/jose'
import * as jose from 'jose'
import { beforeAll, describe, expect, test } from 'vitest'
import { callbacks, getSignJwsCallback } from '../../../../oauth2/src/__tests__/util.mjs'
import { verifyJarRequest } from '../../jar/handle-jar-request/verify-jar-request.js'
import { Openid4vpClient } from '../../Openid4vpClient.js'

const generateKeyPair = async () => {
  const { privateKey, publicKey } = await jose.generateKeyPair('ES256', { extractable: true })
  return { privateJwk: (await jose.exportJWK(privateKey)) as Jwk, publicJwk: (await jose.exportJWK(publicKey)) as Jwk }
}

const now = new Date('2026-01-01T00:00:00.000Z')
const seconds = (date: Date) => Math.floor(date.getTime() / 1000)

// OpenID4VP 1.0 Section 5.9.3 and Section 12
describe('verifyJarRequest with the verifier_attestation client identifier prefix', () => {
  let issuer: Awaited<ReturnType<typeof generateKeyPair>>
  let verifier: Awaited<ReturnType<typeof generateKeyPair>>
  let other: Awaited<ReturnType<typeof generateKeyPair>>
  beforeAll(async () => {
    ;[issuer, verifier, other] = await Promise.all([generateKeyPair(), generateKeyPair(), generateKeyPair()])
  })

  // The wallet trusts attestations signed with the issuer key only. `isJwtTyp` recognizes the typ in every form
  // the library accepts, so an attestation can't pass as another JWT by its casing or `application/` prefix.
  const verifyJws: VerifyJwsCallback = (signer, context) =>
    isJwtTyp(context.protectedHeader.typ, 'verifier-attestation+jwt') &&
    (signer.method !== 'jwk' || signer.publicJwk.x !== issuer.publicJwk.x)
      ? { verified: false }
      : callbacks.verifyJws(signer, context)

  const createAttestation = async (
    payload: Record<string, unknown> = {},
    signedBy = issuer,
    typ = 'verifier-attestation+jwt'
  ) =>
    (
      await signJwt({
        header: { typ, jwk: signedBy.publicJwk },
        payload: {
          iss: 'https://trust.example',
          sub: 'verifier.example',
          exp: seconds(now) + 3600,
          cnf: { jwk: verifier.publicJwk },
          ...payload,
        },
        signer: { method: 'jwk', alg: 'ES256', publicJwk: signedBy.publicJwk },
        signJwsCallback: getSignJwsCallback([signedBy.privateJwk]),
      })
    ).jwt

  const createRequest = async (
    header: Record<string, unknown>,
    { signedBy = verifier, payload = {} }: { signedBy?: typeof verifier; payload?: Record<string, unknown> } = {}
  ) =>
    (
      await signJwt({
        header: { typ: 'oauth-authz-req+jwt', ...header },
        payload: {
          client_id: 'verifier_attestation:verifier.example',
          response_type: 'vp_token',
          response_mode: 'direct_post',
          response_uri: 'https://verifier.example/response',
          nonce: 'nonce',
          // The real clock is past this `exp`, so the tests fail when `now` is not passed on
          exp: seconds(now) + 60,
          ...payload,
        },
        signer: { method: 'jwk', alg: 'ES256', publicJwk: signedBy.publicJwk },
        signJwsCallback: getSignJwsCallback([signedBy.privateJwk]),
      })
    ).jwt

  const verify = (request: string, allowedSkewInSeconds?: number) =>
    verifyJarRequest({
      jarRequestParams: { client_id: 'verifier_attestation:verifier.example', request },
      callbacks: { ...callbacks, verifyJws },
      now,
      allowedSkewInSeconds,
    })

  test('verifies the attestation, and the request with the key in its cnf claim', async () => {
    const result = await verify(await createRequest({ jwt: await createAttestation() }))

    expect(result.verifierAttestation?.payload).toMatchObject({ iss: 'https://trust.example', sub: 'verifier.example' })
    expect(result.signer).toMatchObject({ method: 'jwk', publicJwk: verifier.publicJwk })
  })

  test('rejects a request without a verifier attestation', async () => {
    await expect(verify(await createRequest({}))).rejects.toThrow(
      "requires a Verifier Attestation JWT in the 'jwt' header of the request object"
    )
  })

  test('rejects a request that is not signed with the key in the cnf claim of the attestation', async () => {
    const request = await createRequest({ jwt: await createAttestation(), jwk: other.publicJwk }, { signedBy: other })

    await expect(verify(request)).rejects.toThrow('The signature of the request object could not be verified.')
  })

  test.each([
    ['whose issuer the wallet does not trust', () => createAttestation({}, other)],
    [
      'whose issuer the wallet does not trust, with the typ in its media type form',
      () => createAttestation({}, other, 'application/verifier-attestation+jwt'),
    ],
    [
      'whose issuer the wallet does not trust, with the typ in another casing',
      () => createAttestation({}, other, 'Verifier-Attestation+JWT'),
    ],
    ['for another client identifier', () => createAttestation({ sub: 'other.example' })],
    ['that is expired', () => createAttestation({ exp: seconds(now) - 3600 })],
    ['without a cnf key', () => createAttestation({ cnf: {} })],
  ])('rejects an attestation %s', async (_description, attestation) => {
    await expect(verify(await createRequest({ jwt: await attestation() }))).rejects.toThrow(
      'The verifier attestation of the request object could not be verified.'
    )
  })

  test('rejects a redirect_uri that is not one of the redirect_uris of the attestation', async () => {
    const attestation = await createAttestation({ redirect_uris: ['https://verifier.example/callback'] })
    const request = (redirect_uri: string) =>
      createRequest(
        { jwt: attestation },
        { payload: { response_mode: 'fragment', response_uri: undefined, redirect_uri } }
      )

    await expect(verify(await request('https://verifier.example/callback'))).resolves.toBeDefined()
    await expect(verify(await request('https://attacker.example/callback'))).rejects.toThrow(
      "The 'redirect_uri' of the request is not one of the 'redirect_uris' of the verifier attestation."
    )
  })

  test('rejects a direct_post request, which has no redirect_uri, when the attestation has redirect_uris', async () => {
    const attestation = await createAttestation({ redirect_uris: ['https://verifier.example/callback'] })

    await expect(verify(await createRequest({ jwt: attestation }))).rejects.toThrow(
      "The 'redirect_uri' of the request is not one of the 'redirect_uris' of the verifier attestation."
    )
  })

  test('applies the allowed skew to the attestation', async () => {
    const attestation = await createAttestation({ exp: seconds(now) - 10 })

    await expect(verify(await createRequest({ jwt: attestation }))).resolves.toBeDefined()
    await expect(verify(await createRequest({ jwt: attestation }), 0)).rejects.toThrow(
      'The verifier attestation of the request object could not be verified.'
    )
  })

  test('throws an invalid allowed skew as is, not as an attestation that does not verify', async () => {
    await expect(verify(await createRequest({ jwt: await createAttestation() }), Number.NaN)).rejects.toBeInstanceOf(
      JoseInvalidArgumentError
    )
  })

  test('Openid4vpClient applies its allowed skew to the request object, and a per-call one takes precedence', async () => {
    const request = await createRequest({ jwt: await createAttestation() }, { payload: { exp: seconds(now) - 10 } })
    const resolve = (allowedSkewInSeconds?: number) =>
      new Openid4vpClient({
        callbacks: { ...callbacks, verifyJws, signJws: getSignJwsCallback([]) },
        allowedSkewInSeconds: 0,
      }).resolveOpenid4vpAuthorizationRequest({
        authorizationRequestPayload: { client_id: 'verifier_attestation:verifier.example', request },
        responseMode: { type: 'direct_post' },
        now,
        allowedSkewInSeconds,
      })

    await expect(resolve()).rejects.toMatchObject({ errorResponse: { error: 'invalid_request_object' } })
    await expect(resolve(30)).resolves.toBeDefined()
  })

  test('rejects an expired request object with invalid_request_object, with its payload to send the error to', async () => {
    const request = await createRequest({ jwt: await createAttestation() }, { payload: { exp: seconds(now) - 10 } })

    await expect(verify(request)).resolves.toBeDefined()
    await expect(verify(request, 0)).rejects.toMatchObject({
      errorResponse: { error: 'invalid_request_object', error_description: expect.stringContaining('(expired)') },
      authorizationRequestPayload: { response_uri: 'https://verifier.example/response' },
    })
  })
})
