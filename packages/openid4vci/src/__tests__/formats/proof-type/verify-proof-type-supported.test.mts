import type { Jwk } from '@owf/jose'
import * as jose from 'jose'
import { beforeAll, describe, expect, test } from 'vitest'
import {
  callbacks,
  didJwk,
  getSignJwsCallback,
  signerWithOwnKey,
  verifyJwsTrustingDids,
} from '../../../../../oauth2/src/__tests__/util.mjs'
import {
  createCredentialRequestAttestationProof,
  verifyCredentialRequestAttestationProof,
} from '../../../formats/proof-type/attestation/attestation-proof-type'
import {
  createCredentialRequestJwtProof,
  verifyCredentialRequestJwtProof,
} from '../../../formats/proof-type/jwt/jwt-proof-type'
import { verifyBindingMethodSupported } from '../../../formats/proof-type/verify-proof-type-supported'

const credentialIssuer = 'https://credential-issuer.com'

async function generateEs256Key() {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  return {
    privateJwk: (await jose.exportJWK(privateKey)) as Jwk,
    publicJwk: (await jose.exportJWK(publicKey)) as Jwk,
  }
}

describe('verifying credential request proofs against the credential configuration (OpenID4VCI 1.0 Section 12.2.4)', () => {
  let proofKey: Awaited<ReturnType<typeof generateEs256Key>>
  let jwkProof: string
  let didProof: string

  beforeAll(async () => {
    proofKey = await generateEs256Key()
    jwkProof = await createCredentialRequestJwtProof({
      callbacks: { ...callbacks, signJws: getSignJwsCallback([proofKey.privateJwk]) },
      credentialIssuer,
      nonce: 'nonce',
      signer: { method: 'jwk', alg: 'ES256', publicJwk: proofKey.publicJwk },
    })
    didProof = await createCredentialRequestJwtProof({
      callbacks: { ...callbacks, signJws: getSignJwsCallback([proofKey.privateJwk]) },
      credentialIssuer,
      nonce: 'nonce',
      signer: signerWithOwnKey('did', proofKey.publicJwk),
    })
  })

  const verifyJwtProof = (jwt: string, credentialConfiguration?: object) =>
    verifyCredentialRequestJwtProof({
      callbacks: { ...callbacks, verifyJws: verifyJwsTrustingDids([didJwk(proofKey.publicJwk)]) },
      credentialIssuer,
      expectedNonce: 'nonce',
      jwt,
      credentialConfiguration,
    })

  describe('jwt proof type', () => {
    test('accepts any proof when the credential configuration does not restrict it', async () => {
      await expect(verifyJwtProof(jwkProof, {})).resolves.toBeDefined()
    })

    test('rejects a jwt proof when the credential configuration does not support the jwt proof type', async () => {
      await expect(
        verifyJwtProof(jwkProof, {
          proof_types_supported: { attestation: { proof_signing_alg_values_supported: ['ES256'] } },
        })
      ).rejects.toThrow("Proof type 'jwt' is not supported for the credential configuration")
    })

    test('rejects a proof alg that is not supported (OpenID4VCI 1.0 Appendix F.1)', async () => {
      await expect(
        verifyJwtProof(jwkProof, { proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['EdDSA'] } } })
      ).rejects.toThrow("Proof signing alg value 'ES256' is not supported for proof type 'jwt'")
    })

    test('requires a key attestation when the proof type requires one', async () => {
      await expect(
        verifyJwtProof(jwkProof, {
          proof_types_supported: {
            jwt: { proof_signing_alg_values_supported: ['ES256'], key_attestations_required: {} },
          },
        })
      ).rejects.toThrow('A key attestation is required by the credential issuer, but no key attestation was provided')
    })

    test('accepts a jwk proof key for the jwk and cose_key binding methods', async () => {
      await expect(
        verifyJwtProof(jwkProof, { cryptographic_binding_methods_supported: ['jwk'] })
      ).resolves.toBeDefined()
      await expect(
        verifyJwtProof(jwkProof, { cryptographic_binding_methods_supported: ['cose_key'] })
      ).resolves.toBeDefined()
    })

    test('rejects a jwk proof key when only did binding methods are supported', async () => {
      await expect(verifyJwtProof(jwkProof, { cryptographic_binding_methods_supported: ['did:key'] })).rejects.toThrow(
        "Proof key binding method 'jwk' is not supported for the credential configuration"
      )
    })

    test('matches a did proof key against the did method', async () => {
      await expect(
        verifyJwtProof(didProof, { cryptographic_binding_methods_supported: ['did:jwk'] })
      ).resolves.toBeDefined()
      await expect(
        verifyJwtProof(didProof, { cryptographic_binding_methods_supported: ['did'] })
      ).resolves.toBeDefined()
      await expect(
        verifyJwtProof(didProof, { cryptographic_binding_methods_supported: ['did:key', 'jwk'] })
      ).rejects.toThrow("Proof key binding method 'did:jwk' is not supported for the credential configuration")
    })
  })

  describe('attestation proof type', () => {
    let attestationProof: string
    let attester: Awaited<ReturnType<typeof generateEs256Key>>

    beforeAll(async () => {
      attester = await generateEs256Key()
      attestationProof = await createCredentialRequestAttestationProof({
        callbacks: { signJws: getSignJwsCallback([attester.privateJwk]) },
        attestedKeys: [proofKey.publicJwk],
        nonce: 'nonce',
        expiresAt: new Date(Date.now() + 500 * 1000),
        signer: signerWithOwnKey('did', attester.publicJwk),
      })
    })

    const verifyAttestationProof = (credentialConfiguration?: object) =>
      verifyCredentialRequestAttestationProof({
        callbacks: { ...callbacks, verifyJws: verifyJwsTrustingDids([didJwk(attester.publicJwk)]) },
        keyAttestationJwt: attestationProof,
        expectedNonce: 'nonce',
        credentialConfiguration,
      })

    test('accepts an attestation proof the credential configuration supports', async () => {
      await expect(
        verifyAttestationProof({
          proof_types_supported: { attestation: { proof_signing_alg_values_supported: ['ES256'] } },
          cryptographic_binding_methods_supported: ['cose_key'],
        })
      ).resolves.toBeDefined()
    })

    test('rejects an attestation proof when the credential configuration only supports the jwt proof type', async () => {
      await expect(
        verifyAttestationProof({ proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } } })
      ).rejects.toThrow("Proof type 'attestation' is not supported for the credential configuration")
    })

    test('rejects an attestation signed with an alg that is not supported', async () => {
      await expect(
        verifyAttestationProof({
          proof_types_supported: { attestation: { proof_signing_alg_values_supported: ['EdDSA'] } },
        })
      ).rejects.toThrow("Proof signing alg value 'ES256' is not supported for proof type 'attestation'")
    })

    test('rejects an attestation proof when only did binding methods are supported', async () => {
      await expect(verifyAttestationProof({ cryptographic_binding_methods_supported: ['did:key'] })).rejects.toThrow(
        "Proof key binding method 'jwk' is not supported for the credential configuration"
      )
    })
  })

  describe('binding method of other proof keys', () => {
    test('rejects an x5c proof key when binding methods are advertised, as there is no binding method for it', () => {
      expect(() =>
        verifyBindingMethodSupported({ cryptographic_binding_methods_supported: ['jwk', 'did'] }, { method: 'x5c' })
      ).toThrow("Proof key binding method 'x5c' is not supported for the credential configuration")
    })

    test('accepts an x5c proof key when no binding methods are advertised', () => {
      expect(() => verifyBindingMethodSupported({}, { method: 'x5c' })).not.toThrow()
    })
  })
})
