import { KBJwt } from '@sd-jwt/core'
import { expect, suite, test, vi } from 'vitest'
import { AuthenticationMethodsReferences } from '../responseClaims'
import { createKbJwt } from '../sdJwt'

suite('createKbJwt', () => {
  const mockHasher = vi.fn().mockResolvedValue(new Uint8Array([4, 5, 6]))
  const mockGetRandomValues = vi.fn().mockReturnValue(new Uint8Array([1, 2, 3]))
  const mockSigner = vi.fn().mockResolvedValue('mockedSignature')

  const baseOptions = {
    responseMode: 'direct_post',
    displayLocale: 'en-US',
    amr: [AuthenticationMethodsReferences.Pin, AuthenticationMethodsReferences.BiometricsStrong],
    transactionData: 'testTransactionData',
    transactionDataHashingAlgorithm: 'SHA-256',
    metadataIntegrity: 'metadataIntegrityValue',
    requestIntegrity: 'requestIntegrityValue',
    walletInsanceVersion: '1.0.0',
  }

  const mockCtx = {
    hasher: mockHasher,
    getRandomValues: mockGetRandomValues,
    signer: mockSigner,
  }

  test('creates KB-JWT with combined claims', async () => {
    const kbJwt = new KBJwt({
      header: {
        typ: 'kb+jwt',
        alg: 'ES256',
      },
      payload: {
        iat: Math.floor(Date.now() / 1000),
        aud: 'test-audience',
        nonce: 'test-nonce',
        sd_hash: 'test-sd-hash',
        sub: 'user123',
        name: 'John Doe',
      },
    })

    const signSpy = vi.spyOn(kbJwt, 'sign')
    signSpy.mockResolvedValue('mockedJwt')

    const options = {
      ...baseOptions,
      kbJwt: kbJwt,
    }

    await createKbJwt(options, mockCtx)

    expect(kbJwt.payload).toEqual({
      iat: expect.any(Number),
      aud: 'test-audience',
      nonce: 'test-nonce',
      sd_hash: 'test-sd-hash',
      jti: 'AQID',
      response_mode: 'direct_post',
      display_locale: 'en-US',
      amr: [AuthenticationMethodsReferences.Pin, AuthenticationMethodsReferences.BiometricsStrong],
      transaction_data_hash: 'BAUG',
      transaction_data_hash_alg: 'SHA-256',
      metadata_integrity: 'metadataIntegrityValue',
      request_integrity: 'requestIntegrityValue',
      walletInstanceVersion: '1.0.0',
      sub: 'user123',
      name: 'John Doe',
    })

    signSpy.mockRestore()
  })

  test('throws error when kbJwt payload is undefined', async () => {
    const kbJwt = new KBJwt({
      payload: undefined,
    })

    const options = {
      ...baseOptions,
      kbJwt: kbJwt,
    }

    await expect(createKbJwt(options, mockCtx)).rejects.toThrow('Payload is not defined on the provided kbjwt')
  })

  test('throws error when duplicate claims exist', async () => {
    const kbJwt = new KBJwt({
      header: {
        typ: 'kb+jwt',
        alg: 'ES256',
      },
      payload: {
        iat: Math.floor(Date.now() / 1000),
        aud: 'test-audience',
        nonce: 'test-nonce',
        sd_hash: 'test-sd-hash',
        jti: 'duplicateJti',
      },
    })

    const options = {
      ...baseOptions,
      kbJwt: kbJwt,
    }

    await expect(createKbJwt(options, mockCtx)).rejects.toThrow(
      'Duplicate claims found in both responseClaims and in the payload of the kbJwt: [jti]'
    )
  })

  test('returns unsigned KB-JWT when no signer is provided', async () => {
    const kbJwt = new KBJwt({
      header: {
        typ: 'kb+jwt',
        alg: 'ES256',
      },
      payload: {
        iat: Math.floor(Date.now() / 1000),
        aud: 'test-audience',
        nonce: 'test-nonce',
        sd_hash: 'test-sd-hash',
        sub: 'user123',
        name: 'John Doe',
      },
    })

    const options = {
      ...baseOptions,
      kbJwt: kbJwt,
    }

    const ctxWithoutSigner = {
      hasher: mockHasher,
      getRandomValues: mockGetRandomValues,
    }

    const result = await createKbJwt(options, ctxWithoutSigner)

    expect(result).toBeInstanceOf(KBJwt)
    expect((result as KBJwt).payload).toEqual({
      iat: expect.any(Number),
      aud: 'test-audience',
      nonce: 'test-nonce',
      sd_hash: 'test-sd-hash',
      jti: 'AQID',
      response_mode: 'direct_post',
      display_locale: 'en-US',
      amr: [AuthenticationMethodsReferences.Pin, AuthenticationMethodsReferences.BiometricsStrong],
      transaction_data_hash: 'BAUG',
      transaction_data_hash_alg: 'SHA-256',
      metadata_integrity: 'metadataIntegrityValue',
      request_integrity: 'requestIntegrityValue',
      walletInstanceVersion: '1.0.0',
      sub: 'user123',
      name: 'John Doe',
    })
  })

  test('handles different authentication methods', async () => {
    const kbJwt = new KBJwt({
      header: {
        typ: 'kb+jwt',
        alg: 'ES256',
      },
      payload: {
        iat: Math.floor(Date.now() / 1000),
        aud: 'test-audience',
        nonce: 'test-nonce',
        sd_hash: 'test-sd-hash',
        sub: 'user123',
      },
    })

    const optionsWithDifferentAmr = {
      ...baseOptions,
      amr: [AuthenticationMethodsReferences.HardwareSecuredKey, AuthenticationMethodsReferences.SoftwareSecuredKey],
      kbJwt: kbJwt,
    }

    await createKbJwt(optionsWithDifferentAmr, mockCtx)

    expect(kbJwt.payload).toEqual(
      expect.objectContaining({
        amr: [AuthenticationMethodsReferences.HardwareSecuredKey, AuthenticationMethodsReferences.SoftwareSecuredKey],
      })
    )
  })

  test('handles different response modes', async () => {
    const kbJwt = new KBJwt({
      header: {
        typ: 'kb+jwt',
        alg: 'ES256',
      },
      payload: {
        iat: Math.floor(Date.now() / 1000),
        aud: 'test-audience',
        nonce: 'test-nonce',
        sd_hash: 'test-sd-hash',
        sub: 'user123',
      },
    })

    const optionsWithDifferentMode = {
      ...baseOptions,
      responseMode: 'query',
      kbJwt: kbJwt,
    }

    await createKbJwt(optionsWithDifferentMode, mockCtx)

    expect(kbJwt.payload).toEqual(
      expect.objectContaining({
        response_mode: 'query',
      })
    )
  })

  test('handles different locales', async () => {
    const kbJwt = new KBJwt({
      header: {
        typ: 'kb+jwt',
        alg: 'ES256',
      },
      payload: {
        iat: Math.floor(Date.now() / 1000),
        aud: 'test-audience',
        nonce: 'test-nonce',
        sd_hash: 'test-sd-hash',
        sub: 'user123',
      },
    })

    const optionsWithDifferentLocale = {
      ...baseOptions,
      displayLocale: 'fr-FR',
      kbJwt: kbJwt,
    }

    await createKbJwt(optionsWithDifferentLocale, mockCtx)

    expect(kbJwt.payload).toEqual(
      expect.objectContaining({
        display_locale: 'fr-FR',
      })
    )
  })

  test('handles different hashing algorithms', async () => {
    const kbJwt = new KBJwt({
      header: {
        typ: 'kb+jwt',
        alg: 'ES256',
      },
      payload: {
        iat: Math.floor(Date.now() / 1000),
        aud: 'test-audience',
        nonce: 'test-nonce',
        sd_hash: 'test-sd-hash',
        sub: 'user123',
      },
    })

    const optionsWithDifferentAlgorithm = {
      ...baseOptions,
      transactionDataHashingAlgorithm: 'SHA-512',
      kbJwt: kbJwt,
    }

    await createKbJwt(optionsWithDifferentAlgorithm, mockCtx)

    expect(kbJwt.payload).toEqual(
      expect.objectContaining({
        transaction_data_hash_alg: 'SHA-512',
      })
    )
    expect(mockHasher).toHaveBeenCalledWith('testTransactionData', 'SHA-512')
  })
})
