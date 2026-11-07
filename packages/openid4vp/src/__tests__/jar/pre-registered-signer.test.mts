import { type Jwk, type JwsSigner, jwsHeaderFromSigner, signJwt } from '@owf/jose'
import * as jose from 'jose'
import { describe, expect, test } from 'vitest'
import {
  callbacks,
  getSignJwsCallback,
  getVerifyJwsCallback,
  signerWithOwnKey,
} from '../../../../oauth2/src/__tests__/util.mjs'
import { verifyJarRequest } from '../../jar/handle-jar-request/verify-jar-request.js'

const createRequestObject = async (signer: (publicJwk: Jwk) => JwsSigner) => {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  const publicJwk = { ...((await jose.exportJWK(publicKey)) as Jwk), kid: 'verifier-key' }
  const jwsSigner = signer(publicJwk)
  const { jwt } = await signJwt({
    header: { typ: 'oauth-authz-req+jwt', ...jwsHeaderFromSigner(jwsSigner) },
    payload: {
      client_id: 'bank-verifier',
      response_type: 'vp_token',
      response_mode: 'direct_post',
      response_uri: 'https://verifier.example/response',
      nonce: 'nonce',
      exp: Math.floor(Date.now() / 1000) + 60,
    },
    signer: jwsSigner,
    signJwsCallback: getSignJwsCallback([{ ...((await jose.exportJWK(privateKey)) as Jwk), kid: publicJwk.kid }]),
  })
  return { request: jwt, publicJwk }
}

// OpenID4VP 1.0 Section 5.9: the keys of a pre-registered client are registered with the wallet, but `verifyJws`
// accepts a key from a `jwk` header or a did:jwk, with which anyone could sign a request for any client_id
describe('verifyJarRequest for a pre-registered client', () => {
  test.each(['jwk', 'did'] as const)('rejects a request object signed with a %s signer', async (method) => {
    const { request } = await createRequestObject((publicJwk) => signerWithOwnKey(method, publicJwk))

    await expect(
      verifyJarRequest({ jarRequestParams: { client_id: 'bank-verifier', request }, callbacks })
    ).rejects.toMatchObject({ errorResponse: { error: 'invalid_request_object' } })
  })

  test('verifies a request object signed with a registered key, identified by kid', async () => {
    const { request, publicJwk } = await createRequestObject((publicJwk) => ({
      method: 'custom',
      alg: 'ES256',
      kid: publicJwk.kid,
    }))

    const result = await verifyJarRequest({
      jarRequestParams: { client_id: 'bank-verifier', request },
      callbacks: { ...callbacks, verifyJws: getVerifyJwsCallback({ publicJwks: [publicJwk] }) },
    })
    expect(result.signer).toMatchObject({ method: 'custom', publicJwk })
  })
})
