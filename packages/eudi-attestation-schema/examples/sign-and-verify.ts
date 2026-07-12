/**
 * Example: Build, sign, and verify a SchemaMeta JWT
 *
 * Run from the repository root:
 *   pnpm tsx packages/eudi-attestation-schema/examples/sign-and-verify.ts
 */

import { ES256 } from '@owf/crypto'
import { schemaMeta, schemaURI, signSchemaMeta, trustAuthority, verifySchemaMeta } from '@owf/eudi-attestation-schema'

// ---------------------------------------------------------------------------
// 1. Key material — in production, load from a vault / HSM
// ---------------------------------------------------------------------------

// Self-signed EC P-256 certificate (generated via openssl for demo purposes)
const certificate = `-----BEGIN CERTIFICATE-----
MIIBczCCARmgAwIBAgIUZt2jkmAgIIiw/wpvJU/4yL7ek/YwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yNjAzMTYxODEwMTJaFw0zNjAzMTMxODEwMTJa
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASa6ViW
voU/uOZiBHqFWLE/s+3Ts2K6XT9x2S+abUz/xu48DnP8eL89DQRS8TIUewZbW+H6
GBuyFJjG/mSuqJf+o1MwUTAdBgNVHQ4EFgQUFDKBWF8aGWeDTQHphAhWXs9/J1Aw
HwYDVR0jBBgwFoAUFDKBWF8aGWeDTQHphAhWXs9/J1AwDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNIADBFAiEAibvAwfagitnTA7zKxcl8kuUaU+oBLClK8YXg
s2WfHbwCIAQKqu6+GHkzWH8H0zMPKedvxJp34whrGoIarukWZjjp
-----END CERTIFICATE-----`

// Matching EC P-256 key pair (JWK)
const privateKey = {
  kty: 'EC' as const,
  x: 'mulYlr6FP7jmYgR6hVixP7Pt07Niul0_cdkvmm1M_8Y',
  y: '7jwOc_x4vz0NBFLxMhR7Bltb4foYG7IUmMb-ZK6ol_4',
  crv: 'P-256' as const,
  d: 'tLyuDKbdvUfndRfaH3AmHNFG6kHih59RsYdKGZDtYlE',
}

const publicKey = {
  kty: 'EC' as const,
  x: 'mulYlr6FP7jmYgR6hVixP7Pt07Niul0_cdkvmm1M_8Y',
  y: '7jwOc_x4vz0NBFLxMhR7Bltb4foYG7IUmMb-ZK6ol_4',
  crv: 'P-256' as const,
}

async function main() {
  // -------------------------------------------------------------------------
  // 2. Build a SchemaMeta object
  // -------------------------------------------------------------------------

  const meta = schemaMeta()
    .id('https://catalog.example.com/schemas/pid/1.0.0')
    .version('1.0.0')
    .rulebookURI('https://legislation.example.eu/eidas2/pid-rulebook')
    .rulebookIntegrity('sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw=')
    .attestationLoS('iso_18045_basic')
    .bindingType('key')
    .addSchemaURI(
      schemaURI()
        .format('dc+sd-jwt')
        .uri('https://catalog.example.com/schemas/pid/sd-jwt/1.0.0.json')
        .integrity('sha256-M8H+reBt9Nr/s8CRicJrthAnk7UdWyTyONW0N8Z/Axw=')
        .meta({ vct: 'eu.example.pid.1' })
        .build()
    )
    .addSchemaURI(
      schemaURI()
        .format('mso_mdoc')
        .uri('https://catalog.example.com/schemas/pid/mdoc/1.0.0.json')
        .integrity('sha256-M8H+reBt9Nr/s8CRicJrthAnk7UdWyTyONW0N8Z/Axw=')
        .meta({ doctype_value: 'org.iso.18013.5.1.mDL' })
        .build()
    )
    .addTrustAuthority(trustAuthority().frameworkType('etsi_tl').value('https://trust-list.example.eu/tl.xml').build())
    .build()

  console.log('SchemaMeta:', JSON.stringify(meta, null, 2))

  // -------------------------------------------------------------------------
  // 3. Sign the SchemaMeta as a JWS
  // -------------------------------------------------------------------------

  const signer = await ES256.getSigner(privateKey)

  const signed = await signSchemaMeta({
    schemaMeta: meta,
    keyId: 'catalog-signer-2025',
    certificates: [certificate],
    signer,
  })

  console.log('\nSigned JWS:\n', signed.jws)
  console.log('\nIssued at:', new Date(signed.iat * 1000).toISOString())

  // -------------------------------------------------------------------------
  // 4. Verify the signed SchemaMeta
  // -------------------------------------------------------------------------

  const verifier = await ES256.getVerifier(publicKey)

  const verified = await verifySchemaMeta({
    jws: signed.jws,
    verifier,
  })

  console.log('\nVerified payload:', JSON.stringify(verified.payload, null, 2))
  console.log('Header:', JSON.stringify(verified.header, null, 2))
  console.log('Issued at:', new Date(verified.iat * 1000).toISOString())
}

main()
