/**
 * WebCrypto based callbacks for the tests. The package itself never touches global crypto.
 */
import type { SignatureVerifier, TbsSigner } from '../index'

const HASH = { ES256: 'SHA-256', ES384: 'SHA-384', ES512: 'SHA-512' } as const

export const webCryptoVerifier: SignatureVerifier = async (input) => {
  const alg = input.signatureAlgorithmName
  if (!alg || !(alg in HASH) || !input.publicKey.jwk) return false
  const key = await globalThis.crypto.subtle.importKey(
    'jwk',
    input.publicKey.jwk,
    { name: 'ECDSA', namedCurve: input.publicKey.jwk.crv as string },
    false,
    ['verify']
  )
  return globalThis.crypto.subtle.verify(
    { name: 'ECDSA', hash: HASH[alg as keyof typeof HASH] },
    key,
    new Uint8Array(input.signatureP1363),
    new Uint8Array(input.data)
  )
}

export async function webCryptoSigner(privateJwk: JsonWebKey, hash = 'SHA-256'): Promise<TbsSigner> {
  const key = await globalThis.crypto.subtle.importKey(
    'jwk',
    privateJwk,
    { name: 'ECDSA', namedCurve: privateJwk.crv as string },
    false,
    ['sign']
  )
  return async (tbs) =>
    new Uint8Array(await globalThis.crypto.subtle.sign({ name: 'ECDSA', hash }, key, new Uint8Array(tbs)))
}

export async function generateSubjectKey(namedCurve = 'P-256'): Promise<{ publicJwk: JsonWebKey; spki: Uint8Array }> {
  const pair = await globalThis.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, ['sign', 'verify'])
  return {
    publicJwk: await globalThis.crypto.subtle.exportKey('jwk', pair.publicKey),
    spki: new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', pair.publicKey)),
  }
}
