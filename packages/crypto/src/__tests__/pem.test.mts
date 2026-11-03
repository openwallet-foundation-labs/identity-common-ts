import { describe, expect, it } from 'vitest'
import { base64DerToPem, parseCertificate, parseCertificateChain, pemToDer } from '../pem'

const SAMPLE_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJALRiMLAh0ESOMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RDQTAEFW0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHlS+caJv1JJhqecjF8o
JwBz3GggPLgTTVOp8OZLuzwEN3YWYeEKjXlY5gC0V/pC8F5JuKlOGVTtsDNHJDRy
-----END CERTIFICATE-----`

const SAMPLE_CERT_PEM_CHAIN = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJALRiMLAh0ESOMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RDQTAEFW0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHlS+caJv1JJhqecjF8o
JwBz3GggPLgTTVOp8OZLuzwEN3YWYeEKjXlY5gC0V/pC8F5JuKlOGVTtsDNHJDRy
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END CERTIFICATE-----`

const SAMPLE_EC_KEY_PEM = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIODsC9qnd3cXswPBl3LB6oJjB1gSyIFNB3mBPbMrmbq9oAcGBSuBBAAi
oWQDYgAEIIWHWasDGprf66GnPHCGnp7joPkq8xWL+j9tiESCbPKVD9MBT+0Wnyrm
YGq7kg36FJ6cP2USqMuBGpkF/Zfm
-----END EC PRIVATE KEY-----`

const SAMPLE_RSA_KEY_PEM = `-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKne8lQJ99
-----END RSA PRIVATE KEY-----`

const SAMPLE_PKCS8_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7OwL2qd3dxezA8GX
-----END PRIVATE KEY-----`

describe('pem', () => {
  describe('parseCertificateChain', () => {
    it('should parse a single certificate', () => {
      const result = parseCertificateChain(SAMPLE_CERT_PEM)
      expect(result).toHaveLength(1)
      expect(result[0]).not.toContain('-----BEGIN')
      expect(result[0]).not.toContain('\n')
    })

    it('should parse multiple certificates', () => {
      const result = parseCertificateChain(SAMPLE_CERT_PEM_CHAIN)
      expect(result).toHaveLength(2)
    })

    it('should throw on invalid PEM', () => {
      expect(() => parseCertificateChain('not a cert')).toThrow('No valid certificates found in PEM string')
    })

    it('should throw on empty string', () => {
      expect(() => parseCertificateChain('')).toThrow('No valid certificates found in PEM string')
    })
  })

  describe('parseCertificate', () => {
    it('should parse a single certificate to base64 DER', () => {
      const result = parseCertificate(SAMPLE_CERT_PEM)
      expect(result).not.toContain('-----BEGIN')
      expect(result).not.toContain('\n')
      expect(result.length).toBeGreaterThan(0)
    })

    it('should produce same result as parseCertificateChain for single cert', () => {
      const single = parseCertificate(SAMPLE_CERT_PEM)
      const chain = parseCertificateChain(SAMPLE_CERT_PEM)
      expect(single).toBe(chain[0])
    })

    it('should throw on invalid PEM', () => {
      expect(() => parseCertificate('not a cert')).toThrow('No valid certificate found in PEM string')
    })
  })

  describe('pemToDer', () => {
    it('should extract DER from an EC private key', () => {
      const result = pemToDer(SAMPLE_EC_KEY_PEM)
      expect(result).not.toContain('-----BEGIN')
      expect(result).not.toContain('\n')
      expect(result.length).toBeGreaterThan(0)
    })

    it('should extract DER from an RSA private key', () => {
      const result = pemToDer(SAMPLE_RSA_KEY_PEM)
      expect(result).not.toContain('-----BEGIN')
      expect(result).not.toContain('\n')
      expect(result.length).toBeGreaterThan(0)
    })

    it('should extract DER from a PKCS#8 private key', () => {
      const result = pemToDer(SAMPLE_PKCS8_KEY_PEM)
      expect(result).not.toContain('-----BEGIN')
      expect(result).not.toContain('\n')
      expect(result.length).toBeGreaterThan(0)
    })

    it('should extract DER from a certificate', () => {
      const result = pemToDer(SAMPLE_CERT_PEM)
      expect(result).not.toContain('-----BEGIN')
      expect(result).not.toContain('\n')
      expect(result).toBe(parseCertificate(SAMPLE_CERT_PEM))
    })

    it('should handle PEM with surrounding whitespace', () => {
      const result = pemToDer(`  \n${SAMPLE_EC_KEY_PEM}\n  `)
      expect(result).toBe(pemToDer(SAMPLE_EC_KEY_PEM))
    })

    it('should throw on invalid input', () => {
      expect(() => pemToDer('not a pem')).toThrow('No valid PEM block found')
    })
  })

  describe('untrusted input', () => {
    it('should ignore boundaries with an unsupported or empty label', () => {
      const pem = `-----BEGIN key-----\n-----BEGIN -----\n${SAMPLE_EC_KEY_PEM}`
      expect(pemToDer(pem)).toBe(pemToDer(SAMPLE_EC_KEY_PEM))
    })

    it('should end a certificate at the first post-encapsulation boundary', () => {
      const pem = `${SAMPLE_CERT_PEM}\nAAAA\n-----END CERTIFICATE-----`
      expect(parseCertificateChain(pem)).toEqual([parseCertificate(SAMPLE_CERT_PEM)])
    })

    // The regular expressions used before took quadratic time on input with many pre-encapsulation boundaries
    // and no post-encapsulation boundary.
    const certificateBoundaries = '-----BEGIN CERTIFICATE-----'.repeat(30_000)
    const pemBoundaries = `-----BEGIN  -----${'-----BEGIN  -----a'.repeat(60_000)}`

    it.each([
      ['parseCertificateChain', () => parseCertificateChain(certificateBoundaries)],
      ['parseCertificate', () => parseCertificate(certificateBoundaries)],
      ['pemToDer', () => pemToDer(pemBoundaries)],
    ])('%s should reject many unterminated blocks in linear time', (_, parse) => {
      const start = performance.now()
      expect(parse).toThrow()
      expect(performance.now() - start).toBeLessThan(1000)
    })
  })

  describe('base64DerToPem', () => {
    it('should wrap base64 DER in PEM headers with 64-char lines', () => {
      const base64 = 'A'.repeat(128)
      const pem = base64DerToPem(base64)
      expect(pem).toContain('-----BEGIN CERTIFICATE-----')
      expect(pem).toContain('-----END CERTIFICATE-----')
      const lines = pem.split('\n')
      // header + 2 content lines (64+64) + footer
      expect(lines).toHaveLength(4)
      expect(lines[1]).toHaveLength(64)
      expect(lines[2]).toHaveLength(64)
    })

    it('should handle short input', () => {
      const pem = base64DerToPem('AAAA')
      expect(pem).toBe('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----')
    })
  })
})
