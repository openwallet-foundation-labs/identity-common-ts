import 'reflect-metadata'
import nodeCrypto from 'node:crypto'
import * as x509 from '@peculiar/x509'
import { CoseKey } from '../..'

x509.cryptoProvider.set(nodeCrypto.webcrypto as unknown as Crypto)

/**
 * Self-signed reader certificate + its signing key, for the reader-auth tests.
 */
export async function createReaderCertificate() {
  const keys = (await nodeCrypto.webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as unknown as CryptoKeyPair

  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Reader',
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 60 * 60 * 1000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys,
  })

  const jwk = (await nodeCrypto.webcrypto.subtle.exportKey('jwk', keys.privateKey)) as Record<string, unknown>

  return {
    readerKey: CoseKey.fromJwk({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d, alg: 'ES256' }),
    readerCertificate: new Uint8Array(certificate.rawData),
  }
}
