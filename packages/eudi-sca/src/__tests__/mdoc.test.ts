import { DeviceSignedItems } from '@owf/mdoc'
import { beforeEach, expect, suite, test, vi } from 'vitest'
import { createMdocDeviceResponse } from '../mdoc'
import { AuthenticationMethodsReferences } from '../responseClaims'

suite('createMdocDeviceResponse', () => {
  const mockHasher = vi.fn().mockResolvedValue(new Uint8Array([4, 5, 6]))
  const mockGetRandomValues = vi.fn().mockReturnValue(new Uint8Array([1, 2, 3]))
  const mockCtx = {
    hasher: mockHasher,
    getRandomValues: mockGetRandomValues,
  }

  let mockMdoc: any
  let baseOptions: any

  beforeEach(() => {
    // Reset mocks
    mockHasher.mockClear()
    mockGetRandomValues.mockClear()

    // Create a mock MDOC document with the required structure
    const deviceNamespaces = {
      deviceNamespaces: new Map(),
    }

    mockMdoc = {
      deviceSigned: {
        deviceNamespaces: deviceNamespaces,
      },
    }

    baseOptions = {
      responseMode: 'direct_post',
      displayLocale: 'en-US',
      amr: [AuthenticationMethodsReferences.Pin, AuthenticationMethodsReferences.BiometricsStrong],
      transactionData: 'testTransactionData',
      transactionDataHashingAlgorithm: 'SHA-256',
      metadataIntegrity: 'metadataIntegrityValue',
      requestIntegrity: 'requestIntegrityValue',
      walletInsanceVersion: '1.0.0',
      mdoc: mockMdoc,
    }
  })

  test('adds SCA device namespace to mdoc', async () => {
    const result = await createMdocDeviceResponse(baseOptions, mockCtx)

    // Verify the result is the same mdoc instance
    expect(result).toBe(mockMdoc)

    // Verify the device namespace was added
    const deviceNamespace = result.deviceSigned.deviceNamespaces.deviceNamespaces.get('eu.europa.ec.eudi.sca.1')
    expect(deviceNamespace).toBeInstanceOf(DeviceSignedItems)

    // Verify the response claims are in the device signed items
    const responseClaims = Object.fromEntries(deviceNamespace?.decodedStructure ?? new Map())
    expect(responseClaims).toEqual({
      jti: 'AQID',
      response_mode: 'direct_post',
      display_locale: 'en-US',
      amr: [AuthenticationMethodsReferences.Pin, AuthenticationMethodsReferences.BiometricsStrong],
      transaction_data_hash: new Uint8Array([4, 5, 6]),
      transaction_data_hash_alg: 'SHA-256',
      metadata_integrity: 'metadataIntegrityValue',
      request_integrity: 'requestIntegrityValue',
      walletInstanceVersion: '1.0.0',
    })
  })

  test('throws error when device namespace key already exists', async () => {
    // Add the SCA namespace to the mdoc first
    const existingDeviceSignedItems = new DeviceSignedItems(
      new Map(
        Object.entries({
          existing: 'data',
        })
      )
    )
    mockMdoc.deviceSigned.deviceNamespaces.deviceNamespaces.set('eu.europa.ec.eudi.sca.1', existingDeviceSignedItems)

    await expect(createMdocDeviceResponse(baseOptions, mockCtx)).rejects.toThrow(
      "Device namespace key 'eu.europa.ec.eudi.sca.1' has already been set on the device namespaces"
    )
  })

  test('verifies response claims structure in device namespace', async () => {
    const result = await createMdocDeviceResponse(baseOptions, mockCtx)
    const deviceNamespace = result.deviceSigned.deviceNamespaces.deviceNamespaces.get('eu.europa.ec.eudi.sca.1')
    const responseClaims = Object.fromEntries(deviceNamespace?.decodedStructure ?? new Map())

    // Verify all expected response claims are present and properly structured
    expect(responseClaims).toHaveProperty('jti', 'AQID')
    expect(responseClaims).toHaveProperty('response_mode', 'direct_post')
    expect(responseClaims).toHaveProperty('display_locale', 'en-US')
    expect(responseClaims).toHaveProperty('amr')
    expect(responseClaims.amr.length).toBeGreaterThanOrEqual(2)
    expect(responseClaims).toHaveProperty('transaction_data_hash', new Uint8Array([4, 5, 6]))
    expect(responseClaims).toHaveProperty('transaction_data_hash_alg', 'SHA-256')
    expect(responseClaims).toHaveProperty('metadata_integrity', 'metadataIntegrityValue')
    expect(responseClaims).toHaveProperty('request_integrity', 'requestIntegrityValue')
    expect(responseClaims).toHaveProperty('walletInstanceVersion', '1.0.0')
  })
})
