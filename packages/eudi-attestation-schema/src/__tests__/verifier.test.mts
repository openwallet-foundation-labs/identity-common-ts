import { ES256, parseCertificate } from '@owf/crypto'
import { base64urlEncode } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { schemaMeta, schemaURI } from '../builders'
import { signSchemaMeta } from '../signer'
import { verifySchemaMeta } from '../verifier'

// Self-signed EC P-256 certificate and matching key pair (generated via openssl)
const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIIBczCCARmgAwIBAgIUZt2jkmAgIIiw/wpvJU/4yL7ek/YwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yNjAzMTYxODEwMTJaFw0zNjAzMTMxODEwMTJa
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASa6ViW
voU/uOZiBHqFWLE/s+3Ts2K6XT9x2S+abUz/xu48DnP8eL89DQRS8TIUewZbW+H6
GBuyFJjG/mSuqJf+o1MwUTAdBgNVHQ4EFgQUFDKBWF8aGWeDTQHphAhWXs9/J1Aw
HwYDVR0jBBgwFoAUFDKBWF8aGWeDTQHphAhWXs9/J1AwDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNIADBFAiEAibvAwfagitnTA7zKxcl8kuUaU+oBLClK8YXg
s2WfHbwCIAQKqu6+GHkzWH8H0zMPKedvxJp34whrGoIarukWZjjp
-----END CERTIFICATE-----`

const TEST_PRIVATE_KEY = {
  kty: 'EC',
  x: 'mulYlr6FP7jmYgR6hVixP7Pt07Niul0_cdkvmm1M_8Y',
  y: '7jwOc_x4vz0NBFLxMhR7Bltb4foYG7IUmMb-ZK6ol_4',
  crv: 'P-256',
  d: 'tLyuDKbdvUfndRfaH3AmHNFG6kHih59RsYdKGZDtYlE',
}

const TEST_PUBLIC_KEY = {
  kty: 'EC',
  x: 'mulYlr6FP7jmYgR6hVixP7Pt07Niul0_cdkvmm1M_8Y',
  y: '7jwOc_x4vz0NBFLxMhR7Bltb4foYG7IUmMb-ZK6ol_4',
  crv: 'P-256',
}

const buildTestMeta = () =>
  schemaMeta()
    .id('https://example.com/attestation/verifier')
    .version('1.0.0')
    .rulebookURI('https://example.com/rulebook.md')
    .rulebookIntegrity('sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw=')
    .attestationLoS('iso_18045_basic')
    .bindingType('key')
    .addSchemaURI(
      schemaURI()
        .format('dc+sd-jwt')
        .uri('https://example.com/schema.json')
        .integrity('sha256-M8H+reBt9Nr/s8CRicJrthAnk7UdWyTyONW0N8Z/Axw=')
        .meta({ vct: 'eu.example.test.1' })
        .build()
    )
    .build()

describe('verifySchemaMeta', () => {
  it('should verify and decode a valid signed SchemaMeta', async () => {
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const verifier = await ES256.getVerifier(TEST_PUBLIC_KEY)

    const meta = buildTestMeta()
    const signed = await signSchemaMeta({
      schemaMeta: meta,
      keyId: 'test-key-1',
      signer,
      certificates: [TEST_CERT],
    })

    const result = await verifySchemaMeta({ jws: signed.jws, verifier })

    const { iat: _iat, ...payloadWithoutIat } = result.payload
    expect(payloadWithoutIat).toEqual(meta)
    expect(result.header.alg).toBe('ES256')
    expect(result.header.kid).toBe('test-key-1')
    expect(result.header.typ).toBe('attestation-schema+jwt')
    expect(result.iat).toBeTypeOf('number')
  })

  it('should throw on invalid signature', async () => {
    const keyPair2 = await ES256.generateKeyPair()
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const wrongVerifier = await ES256.getVerifier(keyPair2.publicKey)

    const meta = buildTestMeta()
    const signed = await signSchemaMeta({
      schemaMeta: meta,
      keyId: 'test-key-1',
      signer,
      certificates: [TEST_CERT],
    })

    await expect(verifySchemaMeta({ jws: signed.jws, verifier: wrongVerifier })).rejects.toThrow('Invalid signature')
  })

  it('should throw on invalid JWS format', async () => {
    const verifier = await ES256.getVerifier(TEST_PUBLIC_KEY)

    await expect(verifySchemaMeta({ jws: 'not-a-jws', verifier })).rejects.toThrow()
  })

  it('should throw on invalid SchemaMeta payload', async () => {
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const verifier = await ES256.getVerifier(TEST_PUBLIC_KEY)

    // Manually build a JWS with an invalid payload (has iat but invalid SchemaMeta)
    const header = base64urlEncode(JSON.stringify({ alg: 'ES256', typ: 'attestation-schema+jwt', kid: 'k1' }))
    const payload = base64urlEncode(JSON.stringify({ invalid: true, iat: Math.floor(Date.now() / 1000) }))
    const signingInput = `${header}.${payload}`
    const signature = await signer(signingInput)
    const jws = `${signingInput}.${signature}`

    await expect(verifySchemaMeta({ jws, verifier })).rejects.toThrow('Invalid SchemaMeta payload')
  })

  it('should return typed header with x5c', async () => {
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const verifier = await ES256.getVerifier(TEST_PUBLIC_KEY)

    const meta = buildTestMeta()
    const signed = await signSchemaMeta({
      schemaMeta: meta,
      keyId: 'test-key-1',
      signer,
      certificates: [TEST_CERT],
    })

    const result = await verifySchemaMeta({ jws: signed.jws, verifier })
    expect(result.header.x5c).toEqual([parseCertificate(TEST_CERT)])
  })
})
