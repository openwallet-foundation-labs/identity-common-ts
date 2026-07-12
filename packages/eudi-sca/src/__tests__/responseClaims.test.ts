import { expect, suite, test, vi } from 'vitest'
import { AuthenticationMethodsReferences, createResponseClaims } from '../responseClaims'

suite('createResponseClaims', () => {
  const mockHasher = vi.fn().mockResolvedValue('mockedHash')
  const mockGetRandomValues = vi.fn().mockReturnValue(new Uint8Array([1, 2, 3]))
  const mockCtx = {
    hasher: mockHasher,
    getRandomValues: mockGetRandomValues,
  }

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

  test('creates response claims with all required fields', async () => {
    const result = await createResponseClaims(baseOptions, mockCtx)

    expect(result).toEqual({
      jti: 'AQID',
      response_mode: 'direct_post',
      display_locale: 'en-US',
      amr: [AuthenticationMethodsReferences.Pin, AuthenticationMethodsReferences.BiometricsStrong],
      transaction_data_hash: 'mockedHash',
      transaction_data_hash_alg: 'SHA-256',
      metadata_integrity: 'metadataIntegrityValue',
      request_integrity: 'requestIntegrityValue',
      walletInstanceVersion: '1.0.0',
    })

    expect(mockHasher).toHaveBeenCalledWith('testTransactionData', 'SHA-256')
    expect(mockGetRandomValues).toHaveBeenCalledWith(128 / 8)
  })

  test('requires at least 2 authentication methods', async () => {
    const optionsWithSingleAmr = {
      ...baseOptions,
      amr: [AuthenticationMethodsReferences.Pin],
    }

    await expect(createResponseClaims(optionsWithSingleAmr, mockCtx)).rejects.toThrow()
  })

  test('validates authentication methods are from enum', async () => {
    const optionsWithInvalidAmr = {
      ...baseOptions,
      amr: ['invalid_method' as any, AuthenticationMethodsReferences.Pin],
    }

    await expect(createResponseClaims(optionsWithInvalidAmr, mockCtx)).rejects.toThrow()
  })

  test('handles different response modes', async () => {
    const optionsWithDifferentMode = {
      ...baseOptions,
      responseMode: 'query',
    }

    const result = await createResponseClaims(optionsWithDifferentMode, mockCtx)
    expect(result.response_mode).toBe('query')
  })

  test('handles different locales', async () => {
    const optionsWithDifferentLocale = {
      ...baseOptions,
      displayLocale: 'fr-FR',
    }

    const result = await createResponseClaims(optionsWithDifferentLocale, mockCtx)
    expect(result.display_locale).toBe('fr-FR')
  })

  test('handles different hashing algorithms', async () => {
    const optionsWithDifferentAlgorithm = {
      ...baseOptions,
      transactionDataHashingAlgorithm: 'SHA-512',
    }

    const result = await createResponseClaims(optionsWithDifferentAlgorithm, mockCtx)
    expect(result.transaction_data_hash_alg).toBe('SHA-512')
    expect(mockHasher).toHaveBeenCalledWith('testTransactionData', 'SHA-512')
  })

  test('generates different jti for each call', async () => {
    mockGetRandomValues.mockReturnValueOnce(new Uint8Array([1, 2, 3])).mockReturnValueOnce(new Uint8Array([4, 5, 6]))

    const result1 = await createResponseClaims(baseOptions, mockCtx)
    const result2 = await createResponseClaims(baseOptions, mockCtx)

    expect(result1.jti).toBe('AQID')
    expect(result2.jti).toBe('BAUG')
  })
})
