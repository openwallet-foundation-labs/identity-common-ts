/**
 * Keys, certificates and signed JWTs for the tests, made with the Web Crypto API.
 */
import { digest } from '@owf/crypto'
import { base64url, base64urlEncode } from '@owf/identity-common'
import { createCertificate } from '@owf/x509'
import {
  CA_CERTIFICATE_PEM,
  CA_PRIVATE_JWK,
} from '../../../../packages/eudi-access-certificate/src/__tests__/fixtures.mjs'

export { CA_CERTIFICATE_PEM }

export interface KeyPair {
  privateKey: CryptoKey
  publicJwk: JsonWebKey
}

export async function generateKey(): Promise<KeyPair> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', pair.publicKey)
  return { privateKey: pair.privateKey, publicJwk: { kty, crv, x, y } }
}

/** A compact JWS, signed with ES256 */
export async function signJwt(header: Record<string, unknown>, payload: unknown, privateKey: CryptoKey) {
  const input = `${base64urlEncode(JSON.stringify({ alg: 'ES256', ...header }))}.${base64urlEncode(JSON.stringify(payload))}`
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    new TextEncoder().encode(input)
  )
  return `${input}.${base64url.encode(new Uint8Array(signature))}`
}

/** A certificate for the key, issued by the CA of the access certificate fixtures and valid now */
export async function issueCertificate(publicJwk: JsonWebKey, commonName = 'Example Issuer') {
  const key = await crypto.subtle.importKey('jwk', CA_PRIVATE_JWK, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
  ])
  return createCertificate({
    subject: [
      ['countryName', 'DE'],
      ['commonName', commonName],
    ],
    subjectPublicKey: publicJwk,
    issuerCertificate: CA_CERTIFICATE_PEM,
    serialNumber: '0102',
    notBefore: new Date(Date.now() - 24 * 3600 * 1000),
    notAfter: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    signatureAlgorithm: 'ES256',
    hasher: digest,
    signer: async (tbs) =>
      new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, Uint8Array.from(tbs))),
  })
}
