import { describe, expect, test } from 'vitest'
import { parseCredentialRequest } from '../../credential-request/parse-credential-request'
import { parseDeferredCredentialRequest } from '../../credential-request/parse-deferred-credential-request'
import { verifyCredentialResponseEncryption } from '../../credential-request/verify-credential-response-encryption'
import type { CredentialIssuerMetadata } from '../../metadata/credential-issuer/z-credential-issuer-metadata'
import { Openid4vciVersion } from '../../version'

const jwk = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', alg: 'ECDH-ES' }

const supported = {
  alg_values_supported: ['ECDH-ES'],
  enc_values_supported: ['A128GCM', 'A256GCM'],
  encryption_required: false,
}

const invalidEncryptionParameters = (error_description: string) => ({
  errorResponse: { error: 'invalid_encryption_parameters', error_description },
})

const verify =
  (
    credentialResponseEncryption: Parameters<typeof verifyCredentialResponseEncryption>[0],
    credential_response_encryption?: CredentialIssuerMetadata['credential_response_encryption']
  ) =>
  () =>
    verifyCredentialResponseEncryption(credentialResponseEncryption, { credential_response_encryption })

describe('verifyCredentialResponseEncryption', () => {
  test('accepts supported parameters and no encryption when it is optional', () => {
    expect(verify({ jwk, enc: 'A256GCM' }, supported)).not.toThrow()
    expect(verify(undefined, supported)).not.toThrow()
    expect(verify(undefined, undefined)).not.toThrow()
  })

  test('accepts the alg next to the jwk as sent by earlier drafts', () => {
    const { alg: _, ...jwkWithoutAlg } = jwk
    expect(verify({ jwk: jwkWithoutAlg, alg: 'ECDH-ES', enc: 'A256GCM' }, supported)).not.toThrow()
  })

  test('rejects a request without encryption when the issuer requires it', () => {
    expect(verify(undefined, { ...supported, encryption_required: true })).toThrow(
      expect.objectContaining(
        invalidEncryptionParameters(
          "The credential issuer requires credential response encryption, but the request does not contain 'credential_response_encryption'"
        )
      )
    )
  })

  test('rejects encryption when the issuer does not support it', () => {
    expect(verify({ jwk, enc: 'A256GCM' }, undefined)).toThrow(
      expect.objectContaining(
        invalidEncryptionParameters('The credential issuer does not support credential response encryption')
      )
    )
  })

  test('rejects an alg, enc or zip value the issuer does not support', () => {
    expect(verify({ jwk: { ...jwk, alg: 'RSA-OAEP' }, enc: 'A256GCM' }, supported)).toThrow(
      expect.objectContaining(
        invalidEncryptionParameters("Credential response encryption 'alg' must be one of 'ECDH-ES'")
      )
    )
    expect(verify({ jwk, enc: 'A128CBC-HS256' }, supported)).toThrow(
      expect.objectContaining(
        invalidEncryptionParameters("Credential response encryption 'enc' must be one of 'A128GCM', 'A256GCM'")
      )
    )
    expect(verify({ jwk, enc: 'A256GCM', zip: 'DEF' }, supported)).toThrow(
      expect.objectContaining(
        invalidEncryptionParameters(
          "The credential issuer does not support compression of the credential response ('zip')"
        )
      )
    )
    expect(verify({ jwk, enc: 'A256GCM', zip: 'DEF' }, { ...supported, zip_values_supported: ['DEF'] })).not.toThrow()
  })
})

describe('credential request parsing', () => {
  const issuerMetadata = {
    authorizationServers: [],
    credentialIssuer: {
      credential_issuer: 'https://issuer.com',
      credential_endpoint: 'https://issuer.com/credential',
      credential_configurations_supported: { my_credential: { format: 'dc+sd-jwt', vct: 'hello' } },
      credential_response_encryption: { ...supported, encryption_required: true },
    } satisfies CredentialIssuerMetadata,
    originalDraftVersion: Openid4vciVersion.V1,
    knownCredentialConfigurations: { my_credential: { format: 'dc+sd-jwt' as const, vct: 'hello' } },
  }

  test('parseCredentialRequest checks the encryption against the issuer metadata', () => {
    expect(() =>
      parseCredentialRequest({
        issuerMetadata,
        credentialRequest: { credential_configuration_id: 'my_credential', proofs: { jwt: ['ey.ey.S'] } },
      })
    ).toThrow("the request does not contain 'credential_response_encryption'")
  })

  test('parseDeferredCredentialRequest checks the encryption against the issuer metadata', () => {
    const deferredCredentialRequest = {
      transaction_id: 'tx',
      credential_response_encryption: { jwk, enc: 'A128CBC-HS256' },
    }

    expect(() => parseDeferredCredentialRequest({ deferredCredentialRequest, issuerMetadata })).toThrow(
      "Credential response encryption 'enc' must be one of 'A128GCM', 'A256GCM'"
    )
  })
})
