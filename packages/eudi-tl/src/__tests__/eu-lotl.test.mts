import { base64, hexEncode } from '@owf/identity-common'
import { X509Certificate } from '@peculiar/x509'
import { describe, expect, it } from 'vitest'
import {
  EU_LOTL_ANCHORS_PROVENANCE,
  EU_LOTL_SIGNING_CERTIFICATES,
  getEuLotlTrustAnchors,
  loadEuLotl,
  TrustedListParseException,
  TrustedListSignatureException,
  verifyEuLotlSignature,
} from '../index'
import { SIGNED_TSL_XML, SIGNER_CERT_BASE64 } from './fixtures.mjs'

/**
 * The shipped LOTL signing certificates are a trust anchor, so the suite checks
 * the pinned set itself: that the published metadata describes the bytes that
 * are actually pinned (a mismatch would mean the constant drifted from what a
 * reviewer cross-checked against the Official Journal) and that the set has not
 * silently expired.
 */
describe('EU_LOTL_SIGNING_CERTIFICATES', () => {
  it('ships certificates whose published metadata matches the pinned bytes', async () => {
    expect(EU_LOTL_SIGNING_CERTIFICATES.length).toBeGreaterThan(0)

    for (const entry of EU_LOTL_SIGNING_CERTIFICATES) {
      const der = base64.decode(entry.certificate)
      const certificate = new X509Certificate(entry.certificate)
      expect(certificate.subject).toBe(entry.subject)
      expect(certificate.notAfter.toISOString()).toBe(entry.notAfter)

      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', der as BufferSource))
      expect(hexEncode(digest)).toBe(entry.fingerprintSha256)
    }
  })

  it('records where the pinned set came from', () => {
    expect(EU_LOTL_ANCHORS_PROVENANCE.officialJournal).toMatch(/^https:\/\/eur-lex\.europa\.eu\//)
    expect(EU_LOTL_ANCHORS_PROVENANCE.source).toBe('https://ec.europa.eu/tools/lotl/eu-lotl.xml')
    expect(EU_LOTL_ANCHORS_PROVENANCE.earliestNotAfter).toBe(
      EU_LOTL_SIGNING_CERTIFICATES.map((entry) => entry.notAfter).sort()[0]
    )
  })

  it('has not expired', () => {
    // Deliberately time-dependent: this fails once every shipped certificate is
    // past its notAfter, which is exactly when the set must be refreshed with
    // `scripts/refresh-lotl-anchors.mts`.
    const usable = EU_LOTL_SIGNING_CERTIFICATES.filter((entry) => new Date(entry.notAfter) > new Date())
    expect(usable.length).toBeGreaterThan(0)
  })

  it('exposes the same certificates as DER trust anchors', () => {
    const anchors = getEuLotlTrustAnchors()
    expect(anchors).toHaveLength(EU_LOTL_SIGNING_CERTIFICATES.length)
    expect(anchors[0]).toEqual(base64.decode(EU_LOTL_SIGNING_CERTIFICATES[0].certificate))
  })
})

describe('verifyEuLotlSignature', () => {
  it('fails closed for a list not signed by a pinned LOTL signer', async () => {
    // The fixture is a valid signed list, but its signer is not one of the
    // Commission's LOTL signing certificates.
    await expect(verifyEuLotlSignature(SIGNED_TSL_XML)).rejects.toThrow(TrustedListSignatureException)
  })

  it('honours caller-supplied anchors instead of the shipped default', async () => {
    const { signerCertificateBase64 } = await verifyEuLotlSignature(SIGNED_TSL_XML, {
      trustAnchors: [base64.decode(SIGNER_CERT_BASE64)],
    })
    expect(signerCertificateBase64).toBe(SIGNER_CERT_BASE64)
  })
})

describe('loadEuLotl', () => {
  it('rejects a list that verifies but is not a list of trusted lists', async () => {
    // Pinning the fixture's own signer isolates the profile check from the
    // signature check: the signature is fine, the TSLType is EUgeneric.
    await expect(loadEuLotl(SIGNED_TSL_XML, { trustAnchors: [base64.decode(SIGNER_CERT_BASE64)] })).rejects.toThrow(
      TrustedListParseException
    )
  })
})
