import { timingSafeEqual } from 'node:crypto'
import { p256 } from '@noble/curves/nist.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { CoseKey, type Mac0Context, type Sign1Context } from '../cose'

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

export const macKey = CoseKey.fromJwk({
  kty: 'OCT',
  k: '6yABWE2AiXBRUvKpr7Uw3eivy0ZluF3CYRpQVpCXbpyCOr6t8Sua4oGjVPfQojfUJ70cJ7MnDoyS7H6bY54w3ZJ7PJgLfHn-XwIVGGZoFdP5O_dO_jhu1ABV6Zwv9lpIm6G6Rl7tOs7dQJr7b6S0aT-yOzEmPx6OBxecykwi_pCkqsY2UypCh_0t5QUhyrK1m3TCMZ6yED8hczgmxUQLpY-BfdByL-26ed4mmD85hDdwhsBYP8HuLVYasTjs21jIVb4wr0BqKiK_St8vUzAeQfU7CAQPrNXdW5kns0QvQLU864WpIZrPK3onm_t2hcXA4975Y_uFHXoMsyNBPAbBuA',
  alg: 'HS256',
})
