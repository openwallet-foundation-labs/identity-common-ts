import { base64 } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { loadTrustedList, TrustedListSignatureException, verifyTrustedListSignature } from '../index'
import { SIGNED_TSL_XML, SIGNER_CERT_BASE64, UNSIGNED_TSL_XML } from './fixtures.mjs'

/**
 * Signature verification uses a small signed sample generated once by
 * `scripts/generate-test-fixtures.mts` (enveloped XAdES, RSA-SHA256, exclusive
 * C14N) — the suite only verifies, it never signs.
 */
describe('verifyTrustedListSignature', () => {
  it('verifies the enveloped XAdES signature and reports the signer certificate', async () => {
    const result = await verifyTrustedListSignature(SIGNED_TSL_XML)
    expect(result.signerCertificateBase64).toBe(SIGNER_CERT_BASE64)
  })

  it('accepts the signature when the signer certificate is a pinned trust anchor', async () => {
    await expect(
      verifyTrustedListSignature(SIGNED_TSL_XML, {
        trustAnchors: [base64.decode(SIGNER_CERT_BASE64)],
      })
    ).resolves.toBeDefined()
  })

  it('fails closed when the signer certificate is not a pinned trust anchor', async () => {
    await expect(
      verifyTrustedListSignature(SIGNED_TSL_XML, {
        trustAnchors: [new Uint8Array([1, 2, 3])],
      })
    ).rejects.toThrow(TrustedListSignatureException)
  })

  it('rejects a tampered document', async () => {
    const tampered = SIGNED_TSL_XML.replace('Test Qualified CA S.A.', 'Evil Qualified CA S.A.')
    expect(tampered).not.toBe(SIGNED_TSL_XML)
    await expect(verifyTrustedListSignature(tampered)).rejects.toThrow(TrustedListSignatureException)
  })

  it('rejects a list without a signature', async () => {
    await expect(verifyTrustedListSignature(UNSIGNED_TSL_XML)).rejects.toThrow(TrustedListSignatureException)
  })

  it('verifies through a caller-supplied ("bring your own crypto") engine', async () => {
    const result = await verifyTrustedListSignature(SIGNED_TSL_XML, { crypto: globalThis.crypto })
    expect(result.signerCertificateBase64).toBe(SIGNER_CERT_BASE64)
    // Falls back to the global engine on the next call without an override.
    const fallback = await verifyTrustedListSignature(SIGNED_TSL_XML)
    expect(fallback.signerCertificateBase64).toBe(SIGNER_CERT_BASE64)
  })
})

describe('loadTrustedList', () => {
  it('verifies the signature and returns the parsed list', async () => {
    const tl = await loadTrustedList(SIGNED_TSL_XML, {
      trustAnchors: [base64.decode(SIGNER_CERT_BASE64)],
    })
    expect(tl.schemeOperatorName).toBe('Test Scheme Operator')
    expect(tl.providers).toHaveLength(1)
  })

  it('does not parse when the signature check fails', async () => {
    await expect(loadTrustedList(UNSIGNED_TSL_XML)).rejects.toThrow(TrustedListSignatureException)
  })
})
