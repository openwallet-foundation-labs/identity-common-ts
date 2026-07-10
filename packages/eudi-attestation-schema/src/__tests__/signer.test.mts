import { ES256, parseCertificate } from '@owf/crypto'
import { base64urlDecode } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { schemaMeta, schemaURI } from '../builders'
import { signSchemaMeta } from '../signer'

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

describe('signSchemaMeta', () => {
  const buildTestMeta = () =>
    schemaMeta()
      .id('https://example.com/schema/123')
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

  it('should produce a valid compact JWS', async () => {
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const meta = buildTestMeta()

    const signed = await signSchemaMeta({
      schemaMeta: meta,
      keyId: 'test-key-1',
      signer,
      certificates: [TEST_CERT],
    })

    expect(signed.jws).toBeDefined()
    const parts = signed.jws.split('.')
    expect(parts).toHaveLength(3)
    expect(signed.iat).toBeTypeOf('number')
    expect(signed.iat).toBeLessThanOrEqual(Math.floor(Date.now() / 1000))
  })

  it('should set correct header fields', async () => {
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const meta = buildTestMeta()

    const signed = await signSchemaMeta({
      schemaMeta: meta,
      keyId: 'catalog-signer-2025',
      signer,
      certificates: [TEST_CERT],
    })

    expect(signed.header.alg).toBe('ES256')
    expect(signed.header.typ).toBe('attestation-schema+jwt')
    expect(signed.header.kid).toBe('catalog-signer-2025')
    expect(signed.header.x5c).toEqual([parseCertificate(TEST_CERT)])
  })

  it('should encode the SchemaMeta as the JWS payload', async () => {
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const meta = buildTestMeta()

    const signed = await signSchemaMeta({
      schemaMeta: meta,
      keyId: 'test-key-1',
      signer,
      certificates: [TEST_CERT],
    })

    const [, payloadPart] = signed.jws.split('.')
    const decoded = JSON.parse(base64urlDecode(payloadPart))
    expect(decoded.version).toBe('1.0.0')
    expect(decoded.rulebookURI).toBe('https://example.com/rulebook.md')
    expect(decoded.attestationLoS).toBe('iso_18045_basic')
    expect(decoded.iat).toBeTypeOf('number')
  })

  it('should return the SchemaMeta in the payload field', async () => {
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const meta = buildTestMeta()

    const signed = await signSchemaMeta({
      schemaMeta: meta,
      keyId: 'test-key-1',
      signer,
      certificates: [TEST_CERT],
    })

    expect(signed.payload).toEqual(meta)
  })

  it('should produce a verifiable signature', async () => {
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const verifier = await ES256.getVerifier(TEST_PUBLIC_KEY)
    const meta = buildTestMeta()

    const signed = await signSchemaMeta({
      schemaMeta: meta,
      keyId: 'test-key-1',
      signer,
      certificates: [TEST_CERT],
    })

    const [headerPart, payloadPart, signaturePart] = signed.jws.split('.')
    const signingInput = `${headerPart}.${payloadPart}`
    const isValid = await verifier(signingInput, signaturePart)
    expect(isValid).toBe(true)
  })
})
