import { nowInSeconds, ValidationError } from '@owf/identity-common'
import { JoseValidationError, signJwt } from '@owf/jose'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest'
import {
  getSignJwsCallback,
  getVerifyJwsCallback,
  callbacks as partialCallbacks,
} from '../../../oauth2/src/__tests__/util.mjs'
import { type CredentialIssuerMetadata, type IssuerInfo, Openid4vciClient, Openid4vciIssuer } from '../index.js'

const privateJwk = {
  kid: 'credential-issuer',
  kty: 'EC',
  d: 'IfSdct8njqWDcMaLIO3ZGG-8a61t9acXxxFWFVDFx6Y',
  crv: 'P-256',
  x: 'ghHo8AZRPhIdmR9zO_aab0R7CsDah-XI5zht8GXo71w',
  y: 'Xfx_VfGzNfRVT5cNbi8jKZ3KMgKzqPGHWCT1yklA0UE',
}
const { d: _, ...publicJwk } = privateJwk
// The wallet trusts the key of the credential issuer out of band
const signer = { method: 'custom', alg: 'ES256', kid: privateJwk.kid } as const
const callbacks = {
  ...partialCallbacks,
  fetch,
  signJws: getSignJwsCallback([privateJwk]),
  verifyJws: getVerifyJwsCallback({ publicJwks: [publicJwk] }),
}
const issuer = new Openid4vciIssuer({ callbacks })
const client = new Openid4vciClient({ callbacks })
const credentialIssuerMetadata = {
  credential_issuer: 'https://issuer.example',
  credential_endpoint: 'https://issuer.example/credential',
  credential_configurations_supported: {},
  authorization_servers: ['https://auth.example'],
} satisfies CredentialIssuerMetadata
const issuerInfo: IssuerInfo = [
  { format: 'registration_cert', data: 'registration-certificate-jwt' },
  { format: 'https://example.org/policy', data: { version: 1 } },
]
const metadataUrl = 'https://issuer.example/.well-known/openid-credential-issuer'
const server = setupServer(
  http.get('https://auth.example/.well-known/oauth-authorization-server', () =>
    HttpResponse.json({ issuer: 'https://auth.example', token_endpoint: 'https://auth.example/token' })
  )
)

describe('Issuer info metadata', () => {
  beforeAll(() => {
    server.listen()
    callbacks.fetch = fetch
  })

  afterEach(() => server.resetHandlers())
  afterAll(() => server.close())

  test.each(['json', 'jwt'] as const)('creates and resolves issuer info in %s metadata', async (format) => {
    const metadata = issuer.createCredentialIssuerMetadata({ ...credentialIssuerMetadata, issuer_info: issuerInfo })
    const jwt =
      format === 'jwt'
        ? await issuer.createSignedCredentialIssuerMetadataJwt({ credentialIssuerMetadata: metadata, signer })
        : undefined
    server.use(
      http.get(metadataUrl, () =>
        jwt ? HttpResponse.text(jwt, { headers: { 'Content-Type': 'application/jwt' } }) : HttpResponse.json(metadata)
      )
    )

    const resolved = await client.resolveIssuerMetadata(credentialIssuerMetadata.credential_issuer)
    expect(resolved.credentialIssuer.issuer_info).toEqual(issuerInfo)
    if (jwt) {
      expect(resolved.signedCredentialIssuer?.jwt.payload.issuer_info).toEqual(issuerInfo)
    } else {
      expect(resolved.signedCredentialIssuer).toBeUndefined()
    }
  })

  test.each([
    { issuerInfo: [] },
    { issuerInfo: [{ format: 'registration_cert', data: 'registration-certificate-jwt', credential_ids: [] }] },
  ])('rejects malformed issuer info in JSON metadata: $issuerInfo', async ({ issuerInfo }) => {
    server.use(http.get(metadataUrl, () => HttpResponse.json({ ...credentialIssuerMetadata, issuer_info: issuerInfo })))

    await expect(client.resolveIssuerMetadata(credentialIssuerMetadata.credential_issuer)).rejects.toThrow(
      ValidationError
    )
  })

  test('rejects malformed issuer info in signed metadata', async () => {
    const { jwt } = await signJwt({
      signer,
      signJwsCallback: callbacks.signJws,
      header: { alg: 'ES256', typ: 'openidvci-issuer-metadata+jwt', kid: privateJwk.kid },
      payload: {
        ...credentialIssuerMetadata,
        sub: credentialIssuerMetadata.credential_issuer,
        iat: nowInSeconds(),
        issuer_info: [{ format: 'registration_cert', data: 'registration-certificate-jwt', credential_ids: [] }],
      },
    })
    server.use(http.get(metadataUrl, () => HttpResponse.text(jwt, { headers: { 'Content-Type': 'application/jwt' } })))

    await expect(client.resolveIssuerMetadata(credentialIssuerMetadata.credential_issuer)).rejects.toThrow(
      JoseValidationError
    )
  })
})
