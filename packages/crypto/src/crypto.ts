import { base64UrlToUint8Array, stringToBytes, uint8ArrayToBase64Url } from '@owf/identity-common'

export const generateSalt = (length: number): string => {
  if (length <= 0) {
    return ''
  }
  // a hex is represented by 2 characters, so we split the length by 2
  const array = new Uint8Array(length / 2)
  globalThis.crypto.getRandomValues(array)

  const salt = Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('')

  return salt
}

export async function digest(data: string | ArrayBuffer, algorithm = 'sha-256'): Promise<Uint8Array> {
  const result = await globalThis.crypto.subtle.digest(algorithm, typeof data === 'string' ? stringToBytes(data) : data)
  return new Uint8Array(result)
}

export const getHasher = (algorithm = 'sha-256') => {
  return (data: string) => digest(data, algorithm)
}

// All derived from the subtle functions being called below
type GenerateKeyAlgorithm = RsaHashedKeyGenParams | EcKeyGenParams
type ImportKeyAlgorithm =
  | AlgorithmIdentifier
  | RsaHashedImportParams
  | EcKeyImportParams
  | HmacImportParams
  | AesKeyAlgorithm
type SignAlgorithm = AlgorithmIdentifier | RsaPssParams | EcdsaParams
type VerifyAlgorithm = AlgorithmIdentifier | RsaPssParams | EcdsaParams

export async function generateKeyPair(keyAlgorithm: GenerateKeyAlgorithm) {
  const keyPair = await globalThis.crypto.subtle.generateKey(keyAlgorithm, true, ['sign', 'verify'])

  const publicKeyJWK = await globalThis.crypto.subtle.exportKey('jwk', keyPair.publicKey)
  const privateKeyJWK = await globalThis.crypto.subtle.exportKey('jwk', keyPair.privateKey)

  return { publicKey: publicKeyJWK, privateKey: privateKeyJWK }
}

export async function getSigner(privateKeyJWK: object, keyAlgorithm: ImportKeyAlgorithm, signAlgorithm: SignAlgorithm) {
  const privateKey = await globalThis.crypto.subtle.importKey('jwk', privateKeyJWK, keyAlgorithm, true, ['sign'])

  return async (data: string) => {
    const signature = await globalThis.crypto.subtle.sign(signAlgorithm, privateKey, stringToBytes(data))

    return uint8ArrayToBase64Url(new Uint8Array(signature))
  }
}

export async function getVerifier(
  publicKeyJWK: object,
  keyAlgorithm: ImportKeyAlgorithm,
  verifyAlgorithm: VerifyAlgorithm
) {
  const publicKey = await globalThis.crypto.subtle.importKey('jwk', publicKeyJWK, keyAlgorithm, true, ['verify'])

  return async (data: string, signatureBase64url: string) => {
    const signature = base64UrlToUint8Array(signatureBase64url)
    const isValid = await globalThis.crypto.subtle.verify(
      verifyAlgorithm,
      publicKey,
      signature.buffer as ArrayBuffer,
      stringToBytes(data)
    )

    return isValid
  }
}

export const ES256 = {
  alg: 'ES256',

  _keyAlgorithm: {
    name: 'ECDSA',
    namedCurve: 'P-256',
  },

  _hashAlgorithm: {
    name: 'ECDSA',
    hash: { name: 'sha-256' },
  },

  async generateKeyPair() {
    return await generateKeyPair(ES256._keyAlgorithm)
  },

  async getSigner(privateKeyJWK: object) {
    return await getSigner(privateKeyJWK, ES256._keyAlgorithm, ES256._hashAlgorithm)
  },

  async getVerifier(publicKeyJWK: object) {
    return await getVerifier(publicKeyJWK, ES256._keyAlgorithm, ES256._hashAlgorithm)
  },
}

export const ES384 = {
  alg: 'ES384',

  _keyAlgorithm: {
    name: 'ECDSA',
    namedCurve: 'P-384',
  },

  _hashAlgorithm: {
    name: 'ECDSA',
    hash: { name: 'sha-384' },
  },

  async generateKeyPair() {
    return await generateKeyPair(ES384._keyAlgorithm)
  },

  async getSigner(privateKeyJWK: object) {
    return await getSigner(privateKeyJWK, ES384._keyAlgorithm, ES384._hashAlgorithm)
  },

  async getVerifier(publicKeyJWK: object) {
    return await getVerifier(publicKeyJWK, ES384._keyAlgorithm, ES384._hashAlgorithm)
  },
}

export const ES512 = {
  alg: 'ES512',

  _keyAlgorithm: {
    name: 'ECDSA',
    namedCurve: 'P-521',
  },

  _hashAlgorithm: {
    name: 'ECDSA',
    hash: { name: 'sha-512' },
  },

  async generateKeyPair() {
    return await generateKeyPair(ES512._keyAlgorithm)
  },

  async getSigner(privateKeyJWK: object) {
    return await getSigner(privateKeyJWK, ES512._keyAlgorithm, ES512._hashAlgorithm)
  },

  async getVerifier(publicKeyJWK: object) {
    return await getVerifier(publicKeyJWK, ES512._keyAlgorithm, ES512._hashAlgorithm)
  },
}
