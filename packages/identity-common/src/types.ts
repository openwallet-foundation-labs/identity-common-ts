// This type declaration is from lib.dom.ts
export interface RsaOtherPrimesInfo {
  d?: string
  r?: string
  t?: string
}

export interface JsonWebKey {
  alg?: string
  crv?: string
  d?: string
  dp?: string
  dq?: string
  e?: string
  ext?: boolean
  k?: string
  key_ops?: string[]
  kty?: string
  n?: string
  oth?: RsaOtherPrimesInfo[]
  p?: string
  q?: string
  qi?: string
  use?: string
  x?: string
  y?: string
}

export interface JwtPayload {
  cnf?: {
    jwk: JsonWebKey
  }
  exp?: number
  iat?: number
  [key: string]: unknown
}

export type Base64urlString = string

export type OrPromise<T> = T | Promise<T>

export type Signer = (data: string) => OrPromise<string>
export type Verifier<T = unknown> = (data: string, sig: string, options?: T) => OrPromise<boolean>
export type Hasher = (data: string | ArrayBuffer, alg: string) => OrPromise<Uint8Array>
export type SaltGenerator = (length: number) => OrPromise<string>
export type HasherAndAlg = {
  hasher: Hasher
  alg: string
}

// Sync versions
export type SignerSync = (data: string) => string
export type VerifierSync = (data: string, sig: string) => boolean
export type HasherSync = (data: string, alg: string) => Uint8Array
export type SaltGeneratorSync = (length: number) => string
export type HasherAndAlgSync = {
  hasher: HasherSync
  alg: string
}

// based on https://www.iana.org/assignments/named-information/named-information.xhtml
export const IANA_HASH_ALGORITHMS = [
  'sha-256',
  'sha-256-128',
  'sha-256-120',
  'sha-256-96',
  'sha-256-64',
  'sha-256-32',
  'sha-384',
  'sha-512',
  'sha3-224',
  'sha3-256',
  'sha3-384',
  'sha3-512',
  'blake2s-256',
  'blake2b-256',
  'blake2b-512',
  'k12-256',
  'k12-512',
] as const

export type HashAlgorithm = (typeof IANA_HASH_ALGORITHMS)[number]
