import { ES256 } from '@owf/crypto'
import { describe, expect, it } from 'vitest'
import { schemaMeta, schemaURI } from '../builders'
import { verifyResolveAndBuildDcql } from '../orchestrator'
import { signSchemaMeta } from '../signer'

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

function buildMetaWithIntegrity(integrity?: string) {
  const schemaIntegrity = integrity ?? 'sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw='
  const builder = schemaMeta()
    .id('https://example.com/attestation/pid')
    .version('1.0.0')
    .rulebookURI('https://example.com/rulebook.md')
    .rulebookIntegrity('sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw=')
    .attestationLoS('iso_18045_basic')
    .bindingType('key')

  const schemaBuilder = schemaURI()
    .format('dc+sd-jwt')
    .uri('https://example.com/pid.json')
    .integrity(schemaIntegrity)
    .meta({ vct: 'eu.example.pid.1' })

  return builder.addSchemaURI(schemaBuilder.build()).build()
}

describe('verifyResolveAndBuildDcql', () => {
  it('executes verify -> resolve -> build happy path', async () => {
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const verifier = await ES256.getVerifier(TEST_PUBLIC_KEY)

    const signed = await signSchemaMeta({
      schemaMeta: buildMetaWithIntegrity(),
      keyId: 'test-key',
      signer,
      certificates: [TEST_CERT],
    })

    const result = await verifyResolveAndBuildDcql({
      jws: signed.jws,
      verifier,
      selectedFormats: ['dc+sd-jwt'],
      resolve: async () => ({
        content: '{"type":"object","properties":{"given_name":{"type":"string"},"family_name":{"type":"string"}}}',
      }),
      includeTrustedAuthorities: true,
    })

    expect(result.verified.payload.version).toBe('1.0.0')
    expect(result.resolvedReferences).toHaveLength(1)
    expect(result.dcql.credentials).toEqual([
      {
        id: 'credential-1',
        format: 'dc+sd-jwt',
        meta: { vct_values: ['eu.example.pid.1'] },
        claims: [{ path: ['given_name'] }, { path: ['family_name'] }],
      },
    ])
  })

  it('fails on invalid signature', async () => {
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const keyPair2 = await ES256.generateKeyPair()
    const wrongVerifier = await ES256.getVerifier(keyPair2.publicKey)

    const signed = await signSchemaMeta({
      schemaMeta: buildMetaWithIntegrity(),
      keyId: 'test-key',
      signer,
      certificates: [TEST_CERT],
    })

    await expect(
      verifyResolveAndBuildDcql({
        jws: signed.jws,
        verifier: wrongVerifier,
        selectedFormats: ['dc+sd-jwt'],
        resolve: async () => ({ content: '{}' }),
      })
    ).rejects.toThrow('Invalid signature')
  })

  it('fails on schema reference resolution errors', async () => {
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const verifier = await ES256.getVerifier(TEST_PUBLIC_KEY)

    const signed = await signSchemaMeta({
      schemaMeta: buildMetaWithIntegrity(),
      keyId: 'test-key',
      signer,
      certificates: [TEST_CERT],
    })

    await expect(
      verifyResolveAndBuildDcql({
        jws: signed.jws,
        verifier,
        selectedFormats: ['dc+sd-jwt'],
        resolve: async () => {
          throw new Error('offline')
        },
      })
    ).rejects.toThrow('schemaURIs[0].uri resolve failed: offline')
  })

  it('fails on integrity verification mismatch', async () => {
    const signer = await ES256.getSigner(TEST_PRIVATE_KEY)
    const verifier = await ES256.getVerifier(TEST_PUBLIC_KEY)

    const signed = await signSchemaMeta({
      schemaMeta: buildMetaWithIntegrity('sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
      keyId: 'test-key',
      signer,
      certificates: [TEST_CERT],
    })

    await expect(
      verifyResolveAndBuildDcql({
        jws: signed.jws,
        verifier,
        selectedFormats: ['dc+sd-jwt'],
        resolve: async () => ({ content: '{"type":"object"}' }),
        verifyIntegrity: true,
      })
    ).rejects.toThrow('schemaURIs[0].integrity mismatch')
  })
})
