import crypto from 'node:crypto'
import type { CallbackContext, Jwk } from '@openid4vc/oauth2'
import { ContentType } from '@openid4vc/utils'
import * as jose from 'jose'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest'
import { getSignJwtCallback, callbacks as partialCallbacks } from '../../../oauth2/src/__tests__/util.mjs'
import {
  type CredentialConfigurationSupportedWithFormats,
  type IssuerMetadataResult,
  Openid4vciClient,
  Openid4vciIssuer,
  Openid4vciVersion,
} from '../index.js'

// EC key pair for credential request proofs (same as full-flow test)
const credentialRequestProofJwk = {
  kty: 'EC',
  d: 'b3T5vRCtRPk-iWQs1qZiCH8pmfUp3g6HfobJi4gHKX8',
  crv: 'P-256',
  x: 'ILLpnBYABwKEgkSLnX7Py8jP6MpcQO6t5u232iOdcz8',
  y: 'II3uHcxF5ve3VFtUb1ZGWIxVMyLhynRHDnJa2WPXj9E',
}
const { d: _d, ...credentialRequestProofJwkPublic } = credentialRequestProofJwk

// RSA-OAEP key pair for JWE encryption/decryption
const { publicKey: encryptionPublicKey, privateKey: encryptionPrivateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
})
const encryptionPublicJwk = encryptionPublicKey.export({ format: 'jwk' }) as Jwk
const encryptionJosePrivateKey = encryptionPrivateKey

const server = setupServer()

const encryptJwe: CallbackContext['encryptJwe'] = async (encryptor, payload) => {
  const josePublicKey = await jose.importJWK(encryptor.publicJwk as jose.JWK, encryptor.alg)
  const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(payload))
    .setProtectedHeader({
      alg: encryptor.alg,
      enc: encryptor.enc,
      ...(encryptor.kid ? { kid: encryptor.kid } : {}),
    })
    .encrypt(josePublicKey)
  return { jwe, encryptionJwk: encryptor.publicJwk }
}

const decryptJwe: CallbackContext['decryptJwe'] = async (jwe) => {
  try {
    const { plaintext } = await jose.compactDecrypt(jwe, encryptionJosePrivateKey)
    return {
      decrypted: true as const,
      payload: new TextDecoder().decode(plaintext),
      decryptionJwk: encryptionPublicJwk,
    }
  } catch {
    return { decrypted: false as const }
  }
}

const callbacks = {
  ...partialCallbacks,
  fetch,
  signJwt: getSignJwtCallback([credentialRequestProofJwk]),
  encryptJwe,
  decryptJwe,
}

const issuer = new Openid4vciIssuer({ callbacks })
const client = new Openid4vciClient({ callbacks })

const cNonce = 'cd59b02c-c199-4a31-903a-920a2830d2a4'

const credentialConfigurationsSupported = {
  pidSdJwt: {
    format: 'dc+sd-jwt',
    vct: 'https://sd-jwt.com',
    credential_signing_alg_values_supported: ['ES256'],
    cryptographic_binding_methods_supported: ['jwk'],
    proof_types_supported: {
      jwt: {
        proof_signing_alg_values_supported: ['ES256'],
      },
    },
  },
} satisfies Record<string, CredentialConfigurationSupportedWithFormats>

const credentialRequestEncryption = {
  jwks: {
    keys: [{ ...encryptionPublicJwk, kid: 'credential-request-key', alg: 'RSA-OAEP' }],
  },
  enc_values_supported: ['A256GCM'],
  encryption_required: false,
}

const credentialIssuerMetadata = issuer.createCredentialIssuerMetadata({
  credential_issuer: 'https://oid4vc-ts-issuer.com',
  credential_endpoint: 'https://oid4vc-ts-issuer.com/credential',
  deferred_credential_endpoint: 'https://oid4vc-ts-issuer.com/deferred-credential',
  credential_configurations_supported: credentialConfigurationsSupported,
  credential_response_encryption: {
    alg_values_supported: ['RSA-OAEP'],
    enc_values_supported: ['A256GCM'],
    encryption_required: false,
  },
  credential_request_encryption: credentialRequestEncryption,
})

const issuerMetadata = {
  credentialIssuer: credentialIssuerMetadata,
  authorizationServers: [],
  originalDraftVersion: Openid4vciVersion.Draft15,
  knownCredentialConfigurations: credentialConfigurationsSupported,
} satisfies IssuerMetadataResult

const credentialResponseEncryption = {
  jwk: encryptionPublicJwk,
  alg: 'RSA-OAEP',
  enc: 'A256GCM',
}

async function decryptCredentialRequest(request: Request) {
  expect(request.headers.get('Content-Type')).toBe(ContentType.Jwt)
  const { plaintext } = await jose.compactDecrypt(await request.text(), encryptionJosePrivateKey)
  return JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>
}

beforeAll(() => server.listen())
afterEach(() => server.resetHandlers())
afterAll(() => server.close())

describe('Credential Response Encryption', () => {
  test('issuer encrypts credential response and client decrypts it', async () => {
    server.resetHandlers(
      http.post(credentialIssuerMetadata.credential_endpoint, async ({ request }) => {
        const credentialRequest = await decryptCredentialRequest(request)

        // Verify the request includes credential_response_encryption
        expect(credentialRequest.credential_response_encryption).toEqual(credentialResponseEncryption)

        const parsedCredentialRequest = issuer.parseCredentialRequest({
          issuerMetadata,
          credentialRequest,
        })

        expect(parsedCredentialRequest.credentialResponseEncryption).toEqual(credentialResponseEncryption)

        if (!parsedCredentialRequest.proofs?.jwt) {
          throw new Error('Missing required jwt proofs')
        }

        await issuer.verifyCredentialRequestJwtProof({
          expectedNonce: cNonce,
          issuerMetadata,
          jwt: parsedCredentialRequest.proofs.jwt[0],
        })

        const { credentialResponse, credentialResponseJwt } = await issuer.createCredentialResponse({
          credential: 'some-credential',
          notificationId: '3b926f09-d603-4e8b-a75d-eaa8965f0fe3',
          cNonce: 'd9457e7c-4cf7-461c-a8d0-94221ba865e7',
          cNonceExpiresInSeconds: 500,
          credentialRequest: parsedCredentialRequest,
          credentialResponseEncryption: parsedCredentialRequest.credentialResponseEncryption,
        })

        expect(credentialResponse.credential).toBe('some-credential')
        expect(credentialResponseJwt).toBeDefined()

        return new HttpResponse(credentialResponseJwt, {
          headers: { 'Content-Type': ContentType.Jwt },
        })
      })
    )

    callbacks.fetch = fetch

    const { jwt } = await client.createCredentialRequestJwtProof({
      credentialConfigurationId: 'pidSdJwt',
      issuerMetadata,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: credentialRequestProofJwkPublic,
      },
      nonce: cNonce,
    })

    const result = await client.retrieveCredentials({
      issuerMetadata,
      accessToken: 'test-access-token',
      credentialConfigurationId: 'pidSdJwt',
      proof: {
        proof_type: 'jwt',
        jwt,
      },
      credentialResponseEncryption,
    })

    expect(result.credentialResponse).toEqual({
      credential: 'some-credential',
      notification_id: '3b926f09-d603-4e8b-a75d-eaa8965f0fe3',
      c_nonce: 'd9457e7c-4cf7-461c-a8d0-94221ba865e7',
      c_nonce_expires_in: 500,
    })
  })

  test('issuer encrypts deferred credential response and client decrypts it', async () => {
    server.resetHandlers(
      http.post(credentialIssuerMetadata.deferred_credential_endpoint as string, async ({ request }) => {
        const body = await decryptCredentialRequest(request)
        expect(body.transaction_id).toBe('txn-456')

        const { deferredCredentialResponse, deferredCredentialResponseJwt } =
          await issuer.createDeferredCredentialResponse({
            credentials: [{ credential: 'deferred-credential-value' }],
            credentialResponseEncryption,
          })

        expect(deferredCredentialResponse.credentials).toEqual([{ credential: 'deferred-credential-value' }])
        expect(deferredCredentialResponseJwt).toBeDefined()

        return new HttpResponse(deferredCredentialResponseJwt, {
          headers: { 'Content-Type': ContentType.Jwt },
        })
      })
    )

    callbacks.fetch = fetch

    const result = await client.retrieveDeferredCredentials({
      issuerMetadata,
      accessToken: 'test-access-token',
      transactionId: 'txn-456',
      credentialResponseEncryption,
    })

    expect(result.deferredCredentialResponse.credentials).toEqual([{ credential: 'deferred-credential-value' }])
  })

  test('createCredentialResponse returns plain response when encryption is not requested', async () => {
    const { credentialResponse, credentialResponseJwt } = await issuer.createCredentialResponse({
      credential: 'some-credential',
      credentialRequest: {
        credentialRequest: {
          credential_configuration_id: 'pidSdJwt',
        },
      },
    })

    expect(credentialResponse.credential).toBe('some-credential')
    expect(credentialResponseJwt).toBeUndefined()
  })

  test('client returns not ok when response is not encrypted but encryption was requested', async () => {
    server.resetHandlers(
      // Server ignores the encryption request and returns plain JSON
      http.post(credentialIssuerMetadata.credential_endpoint, () =>
        HttpResponse.json({ credential: 'some-credential' })
      )
    )

    callbacks.fetch = fetch

    const { jwt } = await client.createCredentialRequestJwtProof({
      credentialConfigurationId: 'pidSdJwt',
      issuerMetadata,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: credentialRequestProofJwkPublic,
      },
      nonce: cNonce,
    })

    await expect(
      client.retrieveCredentials({
        issuerMetadata,
        accessToken: 'test-access-token',
        credentialConfigurationId: 'pidSdJwt',
        proof: {
          proof_type: 'jwt',
          jwt,
        },
        credentialResponseEncryption,
      })
    ).rejects.toThrow(
      "Encryption was requested via 'credential_response_encryption' but the credential response was not encrypted"
    )
  })
})

describe('Credential Request Encryption', () => {
  test('encrypts a regular request when explicitly requested', async () => {
    server.resetHandlers(
      http.post(credentialIssuerMetadata.credential_endpoint, async ({ request }) => {
        expect(request.headers.get('Content-Type')).toBe(ContentType.Jwt)
        const encryptedRequest = await request.text()
        const { plaintext, protectedHeader } = await jose.compactDecrypt(encryptedRequest, encryptionJosePrivateKey)
        expect(protectedHeader).toEqual({
          alg: 'RSA-OAEP',
          enc: 'A256GCM',
          kid: 'credential-request-key',
        })
        expect(JSON.parse(new TextDecoder().decode(plaintext))).toMatchObject({
          credential_configuration_id: 'pidSdJwt',
        })
        return HttpResponse.json({ credential: 'request-encrypted-credential' })
      })
    )

    const result = await client.retrieveCredentials({
      issuerMetadata,
      accessToken: 'test-access-token',
      credentialConfigurationId: 'pidSdJwt',
      credentialRequestEncryption: { encrypt: true },
    })

    expect(result.credentialResponse.credential).toBe('request-encrypted-credential')
  })

  test('encrypts a deferred request when explicitly requested', async () => {
    server.resetHandlers(
      http.post(credentialIssuerMetadata.deferred_credential_endpoint as string, async ({ request }) => {
        expect(request.headers.get('Content-Type')).toBe(ContentType.Jwt)
        const encryptedRequest = await request.text()
        const { plaintext, protectedHeader } = await jose.compactDecrypt(encryptedRequest, encryptionJosePrivateKey)
        expect(protectedHeader).toEqual({
          alg: 'RSA-OAEP',
          enc: 'A256GCM',
          kid: 'credential-request-key',
        })
        expect(JSON.parse(new TextDecoder().decode(plaintext))).toMatchObject({ transaction_id: 'txn-encrypted' })
        return HttpResponse.json({ credentials: [{ credential: 'deferred-encrypted-credential' }] })
      })
    )

    const result = await client.retrieveDeferredCredentials({
      issuerMetadata,
      accessToken: 'test-access-token',
      transactionId: 'txn-encrypted',
      credentialRequestEncryption: { encrypt: true },
    })

    expect(result.deferredCredentialResponse.credentials).toEqual([{ credential: 'deferred-encrypted-credential' }])
  })

  test('encrypts regular requests when the issuer requires request encryption', async () => {
    const issuerMetadataWithRequiredEncryption = {
      ...issuerMetadata,
      credentialIssuer: {
        ...credentialIssuerMetadata,
        credential_request_encryption: {
          ...credentialRequestEncryption,
          encryption_required: true,
        },
      },
    } satisfies IssuerMetadataResult

    server.resetHandlers(
      http.post(credentialIssuerMetadata.credential_endpoint, async ({ request }) => {
        const body = await decryptCredentialRequest(request)
        expect(body.credential_configuration_id).toBe('pidSdJwt')
        return HttpResponse.json({ credential: 'required-encryption-credential' })
      })
    )

    const result = await client.retrieveCredentials({
      issuerMetadata: issuerMetadataWithRequiredEncryption,
      accessToken: 'test-access-token',
      credentialConfigurationId: 'pidSdJwt',
    })

    expect(result.credentialResponse.credential).toBe('required-encryption-credential')
  })

  test('keeps regular and deferred requests as JSON when encryption is not needed', async () => {
    const receivedRequests: Array<{ contentType: string | null; body: Record<string, unknown> }> = []
    server.resetHandlers(
      http.post(credentialIssuerMetadata.credential_endpoint, async ({ request }) => {
        receivedRequests.push({
          contentType: request.headers.get('Content-Type'),
          body: (await request.json()) as Record<string, unknown>,
        })
        return HttpResponse.json({ credential: 'plain-credential' })
      }),
      http.post(credentialIssuerMetadata.deferred_credential_endpoint as string, async ({ request }) => {
        receivedRequests.push({
          contentType: request.headers.get('Content-Type'),
          body: (await request.json()) as Record<string, unknown>,
        })
        return HttpResponse.json({ credentials: [{ credential: 'plain-deferred-credential' }] })
      })
    )

    await client.retrieveCredentials({
      issuerMetadata,
      accessToken: 'test-access-token',
      credentialConfigurationId: 'pidSdJwt',
    })
    await client.retrieveDeferredCredentials({
      issuerMetadata,
      accessToken: 'test-access-token',
      transactionId: 'txn-plain',
    })

    expect(receivedRequests).toEqual([
      {
        contentType: ContentType.Json,
        body: expect.objectContaining({ credential_configuration_id: 'pidSdJwt' }),
      },
      {
        contentType: ContentType.Json,
        body: expect.objectContaining({ transaction_id: 'txn-plain' }),
      },
    ])
  })

  test('fails before sending when required request encryption is unavailable', async () => {
    let requestCount = 0
    server.resetHandlers(
      http.post(credentialIssuerMetadata.credential_endpoint, () => {
        requestCount += 1
        return HttpResponse.json({ credential: 'unexpected' })
      }),
      http.post(credentialIssuerMetadata.deferred_credential_endpoint as string, () => {
        requestCount += 1
        return HttpResponse.json({ credentials: [{ credential: 'unexpected' }] })
      })
    )

    const metadataWithoutRequestEncryption = {
      ...issuerMetadata,
      credentialIssuer: {
        ...credentialIssuerMetadata,
        credential_request_encryption: undefined,
      },
    } satisfies IssuerMetadataResult

    await expect(
      client.retrieveCredentials({
        issuerMetadata: metadataWithoutRequestEncryption,
        accessToken: 'test-access-token',
        credentialConfigurationId: 'pidSdJwt',
        credentialResponseEncryption,
      })
    ).rejects.toThrow(/does not support credential request encryption/)

    await expect(
      client.retrieveDeferredCredentials({
        issuerMetadata: metadataWithoutRequestEncryption,
        accessToken: 'test-access-token',
        transactionId: 'txn-no-support',
        credentialResponseEncryption,
      })
    ).rejects.toThrow(/does not support credential request encryption/)

    await expect(
      client.retrieveCredentials({
        issuerMetadata,
        accessToken: 'test-access-token',
        credentialConfigurationId: 'pidSdJwt',
        credentialRequestEncryption: { encrypt: true, kid: 'unknown-key' },
      })
    ).rejects.toThrow(/not advertised by the issuer/)

    await expect(
      client.retrieveDeferredCredentials({
        issuerMetadata,
        accessToken: 'test-access-token',
        transactionId: 'txn-bad-enc',
        credentialRequestEncryption: { encrypt: true, enc: 'A128CBC-HS256' },
      })
    ).rejects.toThrow(/Credential request encryption 'enc'/)

    const clientWithoutEncryptJwe = new Openid4vciClient({
      callbacks: { ...callbacks, encryptJwe: undefined },
    })
    await expect(
      clientWithoutEncryptJwe.retrieveCredentials({
        issuerMetadata,
        accessToken: 'test-access-token',
        credentialConfigurationId: 'pidSdJwt',
        credentialRequestEncryption: { encrypt: true },
      })
    ).rejects.toThrow(/no encryptJwe callback/)

    expect(requestCount).toBe(0)
  })
})
