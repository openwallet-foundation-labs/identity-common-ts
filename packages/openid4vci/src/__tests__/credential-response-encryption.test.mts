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
  type CredentialRequestEncryption,
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
  originalDraftVersion: Openid4vciVersion.V1,
  knownCredentialConfigurations: credentialConfigurationsSupported,
} satisfies IssuerMetadataResult

const credentialResponseEncryption = {
  jwk: encryptionPublicJwk,
  alg: 'RSA-OAEP',
  enc: 'A256GCM',
}

beforeAll(() => server.listen())
afterEach(() => server.resetHandlers())
afterAll(() => server.close())

describe('Credential Response Encryption', () => {
  test('preserves plaintext requests for response encryption with a Draft 15 issuer', async () => {
    const draft15Metadata = {
      ...issuerMetadata,
      credentialIssuer: {
        ...credentialIssuerMetadata,
        credential_request_encryption: undefined,
      },
      originalDraftVersion: Openid4vciVersion.Draft15,
    } satisfies IssuerMetadataResult

    const encryptResponse = async (response: Record<string, unknown>) =>
      new jose.CompactEncrypt(new TextEncoder().encode(JSON.stringify(response)))
        .setProtectedHeader({ alg: 'RSA-OAEP', enc: 'A256GCM' })
        .encrypt(encryptionPublicKey)
    const encryptedResponse = await encryptResponse({ credential: 'legacy-response' })
    const encryptedDeferredResponse = await encryptResponse({
      credentials: [{ credential: 'legacy-deferred-response' }],
    })

    const fetchLegacyIssuer: typeof fetch = async (_input, init) => {
      expect(new Headers(init?.headers).get('Content-Type')).toBe(ContentType.Json)
      if (typeof init?.body !== 'string') {
        throw new Error('Expected a JSON Credential Request body')
      }
      const requestBody = JSON.parse(init.body)
      expect(requestBody.credential_response_encryption).toEqual(credentialResponseEncryption)
      if (requestBody.transaction_id) {
        expect(requestBody.transaction_id).toBe('txn-legacy')
      } else {
        expect(requestBody.credential_configuration_id).toBe('pidSdJwt')
      }
      return new Response(requestBody.transaction_id ? encryptedDeferredResponse : encryptedResponse, {
        headers: { 'Content-Type': ContentType.Jwt },
      })
    }
    const legacyClient = new Openid4vciClient({ callbacks: { ...callbacks, fetch: fetchLegacyIssuer } })

    const result = await legacyClient.retrieveCredentials({
      issuerMetadata: draft15Metadata,
      accessToken: 'test-access-token',
      credentialConfigurationId: 'pidSdJwt',
      credentialResponseEncryption,
    })

    expect(result.credentialResponse.credential).toBe('legacy-response')

    const deferredResult = await legacyClient.retrieveDeferredCredentials({
      issuerMetadata: draft15Metadata,
      accessToken: 'test-access-token',
      transactionId: 'txn-legacy',
      credentialResponseEncryption,
    })

    expect(deferredResult.deferredCredentialResponse.credentials).toEqual([{ credential: 'legacy-deferred-response' }])
  })

  test('issuer encrypts credential response and client decrypts it', async () => {
    server.resetHandlers(
      http.post(credentialIssuerMetadata.credential_endpoint, async ({ request }) => {
        const parsedCredentialRequest = await issuer.parseCredentialRequest({
          issuerMetadata,
          body: await request.text(),
          contentType: request.headers.get('Content-Type') ?? undefined,
        })

        // Verify the request includes credential_response_encryption
        expect(parsedCredentialRequest.credentialRequest.credential_response_encryption).toEqual(
          credentialResponseEncryption
        )
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
        const { deferredCredentialRequest } = await issuer.parseDeferredCredentialRequest({
          issuerMetadata,
          body: await request.text(),
          contentType: request.headers.get('Content-Type') ?? undefined,
        })
        expect(deferredCredentialRequest.transaction_id).toBe('txn-456')
        expect(deferredCredentialRequest.credential_response_encryption).toEqual(credentialResponseEncryption)

        const { deferredCredentialResponse, deferredCredentialResponseJwt } =
          await issuer.createDeferredCredentialResponse({
            credentials: [{ credential: 'deferred-credential-value' }],
            credentialResponseEncryption: deferredCredentialRequest.credential_response_encryption,
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
  test('encrypts a regular request using the first advertised key and enc when selectors are omitted', async () => {
    const alternateKey = { ...encryptionPublicJwk, kid: 'alternate-request-key', alg: 'RSA-OAEP' }
    const issuerMetadataWithChoices = {
      ...issuerMetadata,
      credentialIssuer: {
        ...credentialIssuerMetadata,
        credential_request_encryption: {
          ...credentialRequestEncryption,
          jwks: { keys: [{ ...encryptionPublicJwk, kid: 'credential-request-key', alg: 'RSA-OAEP' }, alternateKey] },
          enc_values_supported: ['A256GCM', 'A128GCM'],
        },
      },
    } satisfies IssuerMetadataResult

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
      issuerMetadata: issuerMetadataWithChoices,
      accessToken: 'test-access-token',
      credentialConfigurationId: 'pidSdJwt',
      credentialRequestEncryption: {},
    })

    expect(result.credentialResponse.credential).toBe('request-encrypted-credential')
  })

  test('uses explicitly selected advertised kid and enc values', async () => {
    const alternateKey = { ...encryptionPublicJwk, kid: 'alternate-request-key', alg: 'RSA-OAEP' }
    const issuerMetadataWithChoices = {
      ...issuerMetadata,
      credentialIssuer: {
        ...credentialIssuerMetadata,
        credential_request_encryption: {
          ...credentialRequestEncryption,
          jwks: { keys: [{ ...encryptionPublicJwk, kid: 'credential-request-key', alg: 'RSA-OAEP' }, alternateKey] },
          enc_values_supported: ['A256GCM', 'A128GCM'],
        },
      },
    } satisfies IssuerMetadataResult

    server.resetHandlers(
      http.post(credentialIssuerMetadata.credential_endpoint, async ({ request }) => {
        expect(request.headers.get('Content-Type')).toBe(ContentType.Jwt)
        const { protectedHeader } = await jose.compactDecrypt(await request.text(), encryptionJosePrivateKey)
        expect(protectedHeader).toEqual({
          alg: 'RSA-OAEP',
          enc: 'A128GCM',
          kid: 'alternate-request-key',
        })
        return HttpResponse.json({ credential: 'request-encrypted-credential' })
      })
    )

    await client.retrieveCredentials({
      issuerMetadata: issuerMetadataWithChoices,
      accessToken: 'test-access-token',
      credentialConfigurationId: 'pidSdJwt',
      credentialRequestEncryption: { kid: 'alternate-request-key', enc: 'A128GCM' },
    })
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
      credentialRequestEncryption: {},
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
        const parsed = await issuer.parseCredentialRequest({
          issuerMetadata: issuerMetadataWithRequiredEncryption,
          body: await request.text(),
          contentType: request.headers.get('Content-Type') ?? undefined,
        })
        expect(parsed.credentialRequest.credential_configuration_id).toBe('pidSdJwt')
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
        credentialRequestEncryption: { kid: 'unknown-key' },
      })
    ).rejects.toThrow(/not advertised by the issuer/)

    await expect(
      client.retrieveDeferredCredentials({
        issuerMetadata,
        accessToken: 'test-access-token',
        transactionId: 'txn-bad-enc',
        credentialRequestEncryption: { enc: 'A128CBC-HS256' },
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
        credentialRequestEncryption: {},
      })
    ).rejects.toThrow('Credential request encryption is configured, but no encryptJwe callback was provided.')

    expect(requestCount).toBe(0)
  })

  test.each([
    [true, false, 'required by the issuer'],
    [false, true, 'required for credential response encryption'],
    [false, false, 'configured'],
  ] as const)(
    'explains missing encryptJwe for issuer-required=%s and response-encryption=%s',
    async (encryptionRequired, responseEncryption, reason) => {
      const client = new Openid4vciClient({
        callbacks: { ...callbacks, encryptJwe: undefined },
      })
      const metadata: IssuerMetadataResult = {
        ...issuerMetadata,
        credentialIssuer: {
          ...credentialIssuerMetadata,
          credential_request_encryption: {
            ...credentialRequestEncryption,
            encryption_required: encryptionRequired,
          },
        },
      }
      const requestEncryptionOptions: CredentialRequestEncryption = {}
      const options = {
        issuerMetadata: metadata,
        accessToken: 'test-access-token',
        credentialResponseEncryption: responseEncryption ? credentialResponseEncryption : undefined,
        credentialRequestEncryption: encryptionRequired || responseEncryption ? undefined : requestEncryptionOptions,
      }
      const message = `Credential request encryption is ${reason}, but no encryptJwe callback was provided.`
      await expect(client.retrieveCredentials({ ...options, credentialConfigurationId: 'pidSdJwt' })).rejects.toThrow(
        message
      )
      await expect(
        client.retrieveDeferredCredentials({ ...options, transactionId: 'txn-missing-callback' })
      ).rejects.toThrow(message)
    }
  )

  test.each(['parseCredentialRequest', 'parseDeferredCredentialRequest'] as const)(
    '%s parses JSON objects and validates its contents without a decryptJwe callback',
    async (method) => {
      const plaintextIssuer = new Openid4vciIssuer({
        callbacks: { ...callbacks, decryptJwe: undefined },
      })
      const options = { issuerMetadata, contentType: ContentType.Json }
      if (method === 'parseCredentialRequest') {
        const parsed = await plaintextIssuer.parseCredentialRequest({
          ...options,
          body: { credential_configuration_id: 'pidSdJwt' },
        })
        expect(parsed.credentialConfigurationId).toBe('pidSdJwt')
      } else {
        const parsed = await plaintextIssuer.parseDeferredCredentialRequest({
          ...options,
          body: { transaction_id: 'txn-plaintext' },
        })
        expect(parsed.deferredCredentialRequest.transaction_id).toBe('txn-plaintext')
      }

      for (const body of ['not JSON', '{}']) {
        await expect(plaintextIssuer[method]({ ...options, body })).rejects.toMatchObject({
          errorResponse: { error: 'invalid_credential_request' },
        })
      }
    }
  )

  test.each(['parseCredentialRequest', 'parseDeferredCredentialRequest'] as const)(
    '%s reports a missing decryptJwe callback as server_error',
    async (method) => {
      const jwe = await encryptJwe(
        {
          method: 'jwk',
          publicJwk: credentialRequestEncryption.jwks.keys[0],
          alg: 'RSA-OAEP',
          enc: 'A256GCM',
          kid: 'credential-request-key',
        },
        JSON.stringify({ transaction_id: 'txn-encrypted' })
      )
      const issuerWithoutDecryptJwe = new Openid4vciIssuer({
        callbacks: { ...callbacks, decryptJwe: undefined },
      })
      const options = {
        issuerMetadata,
        body: jwe.jwe,
        contentType: ContentType.Jwt,
      }
      const parsing =
        method === 'parseCredentialRequest'
          ? issuerWithoutDecryptJwe.parseCredentialRequest(options)
          : issuerWithoutDecryptJwe.parseDeferredCredentialRequest(options)

      await expect(parsing).rejects.toMatchObject({
        status: 500,
        errorResponse: { error: 'server_error' },
        message: expect.stringContaining('No decryptJwe callback'),
        cause: undefined,
      })
    }
  )
})
