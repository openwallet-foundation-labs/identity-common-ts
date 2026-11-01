import { describe, expect, test } from 'vitest'
import { verifyCredentialRequestEncryption } from '../../credential-request/verify-credential-request-encryption'
import type { CredentialIssuerMetadata } from '../../metadata/credential-issuer/z-credential-issuer-metadata'

const jwk = {
  kty: 'EC',
  kid: 'request-key',
  alg: 'ECDH-ES',
  crv: 'P-256',
  x: 'x',
  y: 'y',
}

const supported = {
  jwks: { keys: [jwk] },
  enc_values_supported: ['A128GCM', 'A256GCM'],
  encryption_required: false,
} satisfies NonNullable<CredentialIssuerMetadata['credential_request_encryption']>

const compactJwe = (header: Record<string, unknown>) =>
  `${Buffer.from(JSON.stringify(header)).toString('base64url')}.eA.eA.eA.eA`

const verify = (
  jwe: string,
  credential_request_encryption?: CredentialIssuerMetadata['credential_request_encryption']
) => verifyCredentialRequestEncryption(jwe, { credential_request_encryption })

const invalidEncryptionParameters = expect.objectContaining({
  errorResponse: expect.objectContaining({ error: 'invalid_encryption_parameters' }),
})

interface InvalidJweTestCase {
  description: string
  jwe: string
  metadata?: CredentialIssuerMetadata['credential_request_encryption']
}

describe('verifyCredentialRequestEncryption', () => {
  test('returns the advertised key and protected header for a valid JWE', () => {
    const header = { kid: jwk.kid, alg: jwk.alg, enc: 'A256GCM' }
    expect(verify(compactJwe(header), supported)).toEqual({ jwk, header })
  })

  test('rejects encrypted requests when the issuer does not advertise request encryption', () => {
    expect(() => verify(compactJwe({ kid: jwk.kid, alg: jwk.alg, enc: 'A128GCM' }))).toThrow(
      invalidEncryptionParameters
    )
  })

  test('rejects a three-segment JWS', () => {
    expect(() => verify('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ3YWxsZXQifQ.signature', supported)).toThrow(
      invalidEncryptionParameters
    )
  })

  const invalidJweTestCases: InvalidJweTestCase[] = [
    { description: 'a non-JWE body', jwe: 'not-a-jwe' },
    { description: 'an undecodable header', jwe: 'bm90LWpzb24.eA.eA.eA.eA' },
    { description: 'a missing kid', jwe: compactJwe({ alg: jwk.alg, enc: 'A128GCM' }) },
    { description: 'a missing alg', jwe: compactJwe({ kid: jwk.kid, enc: 'A128GCM' }) },
    { description: 'an unknown kid', jwe: compactJwe({ kid: 'unknown-key', alg: jwk.alg, enc: 'A128GCM' }) },
    { description: 'an alg mismatch', jwe: compactJwe({ kid: jwk.kid, alg: 'RSA-OAEP', enc: 'A128GCM' }) },
    { description: 'an unadvertised enc', jwe: compactJwe({ kid: jwk.kid, alg: jwk.alg, enc: 'A128CBC-HS256' }) },
    {
      description: 'zip when no compression list is present',
      jwe: compactJwe({ kid: jwk.kid, alg: jwk.alg, enc: 'A128GCM', zip: 'DEF' }),
    },
    {
      description: 'zip when compression is advertised',
      jwe: compactJwe({ kid: jwk.kid, alg: jwk.alg, enc: 'A128GCM', zip: 'DEF' }),
      metadata: { ...supported, zip_values_supported: ['DEF'] },
    },
    {
      description: 'a crit header',
      jwe: compactJwe({ kid: jwk.kid, alg: jwk.alg, enc: 'A128GCM', crit: ['example'] }),
    },
  ]

  test.each(invalidJweTestCases)('rejects $description', ({ jwe, metadata = supported }) => {
    expect(() => verify(jwe, metadata)).toThrow(invalidEncryptionParameters)
  })

  test.each([
    { kid: '', alg: jwk.alg, enc: 'A128GCM' },
    { kid: jwk.kid, alg: '', enc: 'A128GCM' },
    { kid: jwk.kid, alg: 'none', enc: 'A128GCM' },
  ])('rejects invalid header parameters before key selection: %j', (header) => {
    expect(() => verify(compactJwe(header), supported)).toThrow(
      expect.objectContaining({
        errorResponse: expect.objectContaining({
          error: 'invalid_encryption_parameters',
          error_description: expect.stringContaining('Unable to decode credential request JWE header:'),
        }),
      })
    )
  })
})
