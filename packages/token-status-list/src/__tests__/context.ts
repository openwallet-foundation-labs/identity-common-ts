import { timingSafeEqual } from 'node:crypto'
import { p256 } from '@noble/curves/nist.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { CoseKey, type Mac0Context, type Sign1Context } from '@owf/cose'
import { base64url, type Hasher } from '@owf/identity-common'
import {
  JoseValidationError,
  type JoseValidationIssue,
  type JwsSigner,
  type SignJwsCallback,
  type VerifyJwsCallback,
} from '@owf/jose'
import { expect } from 'vitest'
import { StatusListValidationError, type StatusListValidationIssue } from '../status-list-error'

const jwsKeyPair = p256.keygen()
// The uncompressed point is 0x04 || x || y
const jwsPublicPoint = p256.Point.fromBytes(jwsKeyPair.publicKey).toBytes(false)
export const jwsPublicJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: base64url.encode(jwsPublicPoint.slice(1, 33)),
  y: base64url.encode(jwsPublicPoint.slice(33)),
}

export const jwsSigner: JwsSigner = { method: 'custom', alg: 'ES256' }

export const signJws: SignJwsCallback = (_signer, { signingInputBytes }) => ({
  signature: base64url.encode(p256.sign(signingInputBytes, jwsKeyPair.secretKey)),
  signerJwk: jwsPublicJwk,
})

export const verifyJws: VerifyJwsCallback = (_signer, { signingInputBytes, signature }) =>
  p256.verify(base64url.decode(signature), signingInputBytes, jwsKeyPair.publicKey)
    ? { verified: true, signerJwk: jwsPublicJwk }
    : { verified: false }

/** Matches a `JoseValidationError` with an issue of `code` at `claim`. */
export const claimIssue = (claim: string, code: JoseValidationIssue['code']) =>
  expect.objectContaining({
    name: JoseValidationError.name,
    issues: expect.arrayContaining([expect.objectContaining({ code, path: [claim] })]),
  })

/** Matches a `StatusListValidationError` with an issue of `code`, with `context` when given. */
export const statusListIssue = (code: StatusListValidationIssue['code'], context?: object) =>
  expect.objectContaining({
    name: StatusListValidationError.name,
    issues: [expect.objectContaining({ code, ...(context && { context }) })],
  })

export const sign1Context: Sign1Context = {
  sign: async (input) => {
    const { key, toBeSigned } = input
    return p256.sign(toBeSigned, key.privateKey, { format: 'compact' })
  },
  verify: async (input) => {
    const { signature, toBeVerified, key } = input
    return p256.verify(signature, toBeVerified, key instanceof CoseKey ? key.publicKey : key, {
      lowS: false,
    })
  },
}

export const mac0Context: Mac0Context = {
  authenticate: async (input) => {
    const { key, toBeAuthenticated } = input
    const keyBytes = key instanceof CoseKey ? key.privateKey : key
    return hmac(sha256, keyBytes, toBeAuthenticated)
  },
  verify: async (input) => {
    const { tag, toBeAuthenticated, key } = input
    return timingSafeEqual(tag, hmac(sha256, key instanceof CoseKey ? key.privateKey : key, toBeAuthenticated))
  },
}

export const signKey = CoseKey.fromJwk({
  kty: 'EC',
  crv: 'P-256',
  alg: 'ES256',
  x: 'usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8',
  y: 'IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4',
  d: 'V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM',
})

// A second key pair, to check that a token does not verify against a key that did not sign it.
export const otherSignKey = CoseKey.fromJwk({
  kty: 'EC',
  crv: 'P-256',
  alg: 'ES256',
  x: 'R7D-W2d9MEVRN_5P23yN9SodkjMEHI2Np_YHD02eTCQ',
  y: 'c5Ynunf6XyarMKXt0hWEezNzsZv01uQpCnpT-qJoll8',
})

export const macKey = CoseKey.fromJwk({
  kty: 'OCT',
  k: '6yABWE2AiXBRUvKpr7Uw3eivy0ZluF3CYRpQVpCXbpyCOr6t8Sua4oGjVPfQojfUJ70cJ7MnDoyS7H6bY54w3ZJ7PJgLfHn-XwIVGGZoFdP5O_dO_jhu1ABV6Zwv9lpIm6G6Rl7tOs7dQJr7b6S0aT-yOzEmPx6OBxecykwi_pCkqsY2UypCh_0t5QUhyrK1m3TCMZ6yED8hczgmxUQLpY-BfdByL-26ed4mmD85hDdwhsBYP8HuLVYasTjs21jIVb4wr0BqKiK_St8vUzAeQfU7CAQPrNXdW5kns0QvQLU864WpIZrPK3onm_t2hcXA4975Y_uFHXoMsyNBPAbBuA',
  alg: 'HS256',
})

const textEncoder = new TextEncoder()

export const hasher: Hasher = (data) =>
  sha256(typeof data === 'string' ? textEncoder.encode(data) : new Uint8Array(data))
