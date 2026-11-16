import { readFileSync } from 'node:fs'
import { hasher as digest, ES256 } from '@owf/crypto'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { SdJwtVcInstance } from '..'

type Vector = {
  id: string
  layer: string
  expected: 'accept' | 'reject'
  presentation: string
  status_list?: { uri: string; response: string | null }
}

const vectorsFile = JSON.parse(
  readFileSync(new URL('./polaris-negative-vectors/vectors.json', import.meta.url), 'utf8')
) as { settings: Record<string, any>; vectors: Vector[] }
const { settings } = vectorsFile

// Each vector's `clauses` field names the specification sections its verdict rests on.
// The layers this package verifies. The issuer key is the one in settings.issuer_jwks.
const layers = ['control', 'jose', 'sd-jwt', 'sd-jwt-vc', 'openid4vp', 'status-list']
const vectors = vectorsFile.vectors.filter((vector) => layers.includes(vector.layer))
const controls = vectors.filter((vector) => vector.expected === 'accept')
const refused = vectors.filter((vector) => vector.expected === 'reject')

// The first line of the error each vector is refused with
const reasons: Record<string, string> = {
  'issuer-crit': 'Verify Error: unsupported critical header parameters',
  'kb-crit': 'Verify Error: unsupported critical header parameters in Key Binding JWT',
  'kb-aud-array': 'Invalid Key Binding Jwt',
  'kb-aud-no-prefix': 'Verify Error: Invalid Key Binding audience',
  'digest-twice': 'Duplicate digest found in SD-JWT payload',
  'claim-overwrite': 'Disclosed claim name "given_name" conflicts with existing payload key',
  'disclosed-exp': 'Protected claims must not be selectively disclosed: exp',
  'disclosed-iss': 'Protected claims must not be selectively disclosed: iss',
  'disclosure-four-elements': 'Invalid disclosure data',
  'disclosure-named-sd': 'Reserved disclosure claim name "_sd" is not allowed',
  'kb-typ-jwt': 'Invalid Key Binding Jwt',
  'kb-alg-none': 'Verify Error: Invalid JWT',
  'kb-alg-hs256': 'Verify Error: Invalid JWT Signature',
  'kb-iat-nan': 'Invalid JWT as input',
  'kb-exp-string': 'Verify Error: JWT exp must be a number',
  'issuer-sig-der': 'Verify Error: Invalid JWT Signature',
  'kb-aud-missing': 'Invalid Key Binding Jwt',
  'kb-nonce-missing': 'Invalid Key Binding Jwt',
  'status-list-unreachable': 'Could not fetch either a JWT or CWT as status list. Failed to fetch',
  'status-list-not-a-token': 'Unable to parse the JWS, a compact JWS must consist of exactly three parts',
  'status-list-lst-truncated': 'The status list cannot be decompressed',
  'status-list-wrong-key': 'Status List JWT verification failed: Verify Error: Invalid JWT Signature',
  'status-list-no-authority': 'Status List JWT verification failed: Verify Error: Invalid JWT Signature',
  'status-list-expired': 'Status List JWT verification failed: Verify Error: JWT is expired',
  'status-list-index-past-end': 'Index out of bounds: 16 is not an index of a list of 16 statuses',
}

// Each status list vector states what its uri answers: a Status List Token, another body, or nothing
const server = setupServer()
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => server.resetHandlers())
afterAll(() => server.close())

const verify = async (vector: Vector) => {
  const statusList = vector.status_list
  if (statusList) {
    server.use(
      http.get(statusList.uri, () =>
        statusList.response === null
          ? HttpResponse.error()
          : new HttpResponse(statusList.response, { headers: { 'content-type': 'application/statuslist+jwt' } })
      )
    )
  }
  const { kty, crv, x, y } = settings.issuer_jwks[0]
  const sdJwtVc = new SdJwtVcInstance({
    hasher: digest,
    verifier: await ES256.getVerifier({ kty, crv, x, y }),
    kbVerifier: async (data, signature, payload) =>
      payload.cnf !== undefined && (await ES256.getVerifier(payload.cnf.jwk))(data, signature),
  })
  return sdJwtVc.verify(vector.presentation, {
    keyBindingNonce: settings.nonce,
    expectedKeyBindingAudience: settings.audience,
    expectedVct: settings.vct,
    currentDate: settings.now,
    skewSeconds: settings.max_skew_seconds,
  })
}

describe('Polaris negative vectors for SD-JWT VC presentations', () => {
  it('runs 3 controls and 25 vectors to refuse, each with its reason', () => {
    expect(controls).toHaveLength(3)
    expect(refused).toHaveLength(25)
    expect(refused.map((vector) => vector.id).sort()).toEqual(Object.keys(reasons).sort())
  })

  it.each(controls)('verifies the control $id', async (vector) => {
    await expect(verify(vector)).resolves.toBeDefined()
  })

  it.each(refused)('refuses $id ($layer)', async (vector) => {
    const error = await verify(vector).then(
      () => undefined,
      (error: unknown) => error
    )
    expect(error).toBeInstanceOf(Error)
    expect((error as Error).message.split('\n')[0]).toBe(reasons[vector.id])
  })
})
