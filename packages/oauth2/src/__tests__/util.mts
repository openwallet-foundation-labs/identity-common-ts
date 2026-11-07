import crypto, { webcrypto } from 'node:crypto'
import { base64url, bytesToString, stringToBytes } from '@owf/identity-common'
import { calculateJwkThumbprint, type Jwk, type JwsSigner } from '@owf/jose'
import * as jose from 'jose'
import type { CallbackContext, SignJwsCallback, VerifyJwsCallback } from '../callbacks'
import { clientAuthenticationNone } from '../client-authentication'

// Needed for Node 18 support with jose6. We can soon drop node18 support.
if (process.versions.node.startsWith('18.')) {
  // @ts-expect-error
  globalThis.crypto = webcrypto
}

export function parseXwwwFormUrlEncoded(text: string) {
  return Object.fromEntries(Array.from(new URLSearchParams(text).entries()))
}

/**
 * The WebCrypto parameters for the JWA algorithms these tests use. The callbacks sign and verify the
 * signing input directly, so the signature algorithm has to be named here rather than being taken
 * from a jwt library.
 */
const subtleAlgorithm = (alg: string): AlgorithmIdentifier | EcdsaParams | RsaPssParams => {
  switch (alg) {
    case 'ES256':
      return { name: 'ECDSA', hash: 'SHA-256' }
    case 'ES384':
      return { name: 'ECDSA', hash: 'SHA-384' }
    case 'ES512':
      return { name: 'ECDSA', hash: 'SHA-512' }
    case 'EdDSA':
    case 'Ed25519':
      return { name: 'Ed25519' }
    case 'RS256':
    case 'RS384':
    case 'RS512':
      return { name: 'RSASSA-PKCS1-v1_5' }
    case 'PS256':
      return { name: 'RSA-PSS', saltLength: 32 }
    case 'PS384':
      return { name: 'RSA-PSS', saltLength: 48 }
    case 'PS512':
      return { name: 'RSA-PSS', saltLength: 64 }
    default:
      throw new Error(`Unsupported alg '${alg}' in test callbacks`)
  }
}

/**
 * An attester the test callbacks trust by its `kid`, as a server trusts its attesters out of band. Client and key
 * attestations are signed with its `signer`, since a `jwk` or `did` signer is rejected for them.
 */
export const testAttester = await (async () => {
  const kid = 'test-attester'
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  return {
    signer: { method: 'custom', alg: 'ES256', kid } as const,
    privateJwk: { ...(await jose.exportJWK(privateKey)), kid } as Jwk,
    publicJwk: { ...(await jose.exportJWK(publicKey)), kid } as Jwk,
  }
})()

/** A signer with a key its holder chose: in a `jwk` header, or in a did:jwk. */
export const signerWithOwnKey = (method: 'jwk' | 'did', publicJwk: Jwk): JwsSigner =>
  method === 'jwk'
    ? { method, alg: 'ES256', publicJwk }
    : { method, alg: 'ES256', didUrl: `did:jwk:${base64url.encode(stringToBytes(JSON.stringify(publicJwk)))}#0` }

/** The public jwk a signer identifies, for the signer methods these tests use. */
function publicJwkForSigner(signer: Parameters<SignJwsCallback>[0], jwks: Jwk[]): Jwk {
  if (signer.method === 'did') {
    return JSON.parse(bytesToString(base64url.decode(signer.didUrl.split('#')[0].replace('did:jwk:', ''))))
  }

  if (signer.method === 'jwk') {
    return signer.publicJwk
  }

  if (signer.method === 'federation' || signer.method === 'custom') {
    const jwk = jwks.find((jwk) => jwk.kid === signer.kid)
    if (!jwk) throw new Error(`No jwk found for kid ${signer.kid}`)
    const { d: _d, ...publicJwk } = jwk
    return publicJwk
  }

  throw new Error('Signer method not supported')
}

export function getVerifyJwsCallback({ publicJwks }: { publicJwks?: Jwk[] } = {}): VerifyJwsCallback {
  return async (signer, { signingInputBytes, signature }) => {
    const jwk = publicJwkForSigner(signer, [...(publicJwks ?? []), testAttester.publicJwk])
    const key = (await jose.importJWK(jwk as jose.JWK, signer.alg)) as CryptoKey

    const verified = await globalThis.crypto.subtle.verify(
      subtleAlgorithm(signer.alg),
      key,
      decodeBase64Url(signature),
      signingInputBytes as Uint8Array<ArrayBuffer>
    )

    return verified ? { verified: true, signerJwk: jwk } : { verified: false }
  }
}

export const callbacks = {
  hash: (data, alg) =>
    crypto
      .createHash(alg.replace('-', '').toLowerCase())
      .update(typeof data === 'string' ? data : new Uint8Array(data))
      .digest(),
  generateRandom: (bytes) => crypto.randomBytes(bytes),
  clientAuthentication: clientAuthenticationNone({
    clientId: 'some-random-client-id',
  }),
  verifyJws: getVerifyJwsCallback(),
  encryptJwe: async (encryptor, payload) => {
    const josePublicKey = await jose.importJWK(encryptor.publicJwk as jose.JWK, encryptor.alg)
    const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(payload))
      .setProtectedHeader({ alg: encryptor.alg, enc: encryptor.enc })
      .encrypt(josePublicKey)
    return { jwe, encryptionJwk: encryptor.publicJwk }
  },
  decryptJwe: async (_jwe) => {
    // Note: In real usage, you'd need the private key to decrypt.
    // This is a placeholder that always returns decrypted: false for tests.
    return { decrypted: false as const }
  },
} as const satisfies Partial<CallbackContext>

export const getSignJwsCallback = (callerPrivateJwks: Jwk[]): SignJwsCallback => {
  const privateJwks = [...callerPrivateJwks, testAttester.privateJwk]
  return async (signer, { signingInputBytes }) => {
    const jwk = publicJwkForSigner(signer, privateJwks)

    const jwkThumbprint = await calculateJwkThumbprint({
      jwk,
      hashAlgorithm: 'sha-256',
      hashCallback: callbacks.hash,
    })

    const privateJwk = await Promise.all(
      privateJwks.map(async (jwk) =>
        (await calculateJwkThumbprint({
          hashAlgorithm: 'sha-256',
          hashCallback: callbacks.hash,
          jwk,
        })) === jwkThumbprint
          ? jwk
          : undefined
      )
    ).then((jwks) => jwks.find((jwk) => jwk !== undefined))

    if (!privateJwk) {
      throw new Error(`No private key available for public jwk \n${JSON.stringify(jwk, null, 2)}`)
    }

    const key = (await jose.importJWK(privateJwk as jose.JWK, signer.alg)) as CryptoKey
    const signature = await globalThis.crypto.subtle.sign(
      subtleAlgorithm(signer.alg),
      key,
      signingInputBytes as Uint8Array<ArrayBuffer>
    )

    return { signature: base64url.encode(new Uint8Array(signature)), signerJwk: jwk }
  }
}

function decodeBase64Url(input: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(input, 'base64url')) as Uint8Array<ArrayBuffer>
}
