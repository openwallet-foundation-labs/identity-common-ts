import { describe, expect, it } from 'vitest'
import { JoseAlgorithmNotAllowedError } from '../error'
import { assertKeyAllowedForSignatureAlgorithm } from '../jwa/key-compatibility'

const ed25519Key = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }
const ed448Key = {
  kty: 'OKP',
  crv: 'Ed448',
  x: 'X9dEm1m0Yf0s54fsYWrUah2hNCSFpw4fig6nXYDpZ3jt8SR2m0bHBhvWeD3x5Q9s0foavq_oJWGA',
}
const message = 'Unable to use the key with the algorithm of the token.'

/**
 * RFC 9864 deprecates the polymorphic `EdDSA` in favour of `Ed25519` and `Ed448`, which are the same
 * signature algorithm with the curve fixed. Keys labelled with one and tokens labelled with the other
 * are both in use while the ecosystem moves over.
 */
describe('EdDSA keys and the fully specified EdDSA algorithms', () => {
  it('accepts a key declaring EdDSA for an Ed25519 token', () => {
    expect(() =>
      assertKeyAllowedForSignatureAlgorithm({ jwk: { ...ed25519Key, alg: 'EdDSA' }, alg: 'Ed25519' })
    ).not.toThrow()
  })

  it('accepts a key declaring EdDSA for an Ed448 token', () => {
    expect(() =>
      assertKeyAllowedForSignatureAlgorithm({ jwk: { ...ed448Key, alg: 'EdDSA' }, alg: 'Ed448' })
    ).not.toThrow()
  })

  it('accepts a key declaring Ed25519 for an EdDSA token', () => {
    expect(() =>
      assertKeyAllowedForSignatureAlgorithm({ jwk: { ...ed25519Key, alg: 'Ed25519' }, alg: 'EdDSA' })
    ).not.toThrow()
  })

  it('accepts a key declaring Ed448 for an EdDSA token', () => {
    expect(() =>
      assertKeyAllowedForSignatureAlgorithm({ jwk: { ...ed448Key, alg: 'Ed448' }, alg: 'EdDSA' })
    ).not.toThrow()
  })

  it('rejects a key declaring EdDSA on Ed448 for an Ed25519 token', () => {
    expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk: { ...ed448Key, alg: 'EdDSA' }, alg: 'Ed25519' })).toThrow(
      new JoseAlgorithmNotAllowedError(
        `${message} Algorithm 'Ed25519' requires a key with crv 'Ed25519', but the key has crv 'Ed448'.`
      )
    )
  })

  it('rejects a key declaring Ed25519 on Ed448 for an EdDSA token', () => {
    expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk: { ...ed448Key, alg: 'Ed25519' }, alg: 'EdDSA' })).toThrow(
      new JoseAlgorithmNotAllowedError(
        `${message} Algorithm 'Ed25519' requires a key with crv 'Ed25519', but the key has crv 'Ed448'.`
      )
    )
  })

  it('rejects a key declaring Ed25519 for an Ed448 token', () => {
    expect(() =>
      assertKeyAllowedForSignatureAlgorithm({ jwk: { ...ed25519Key, alg: 'Ed25519' }, alg: 'Ed448' })
    ).toThrow(
      new JoseAlgorithmNotAllowedError(`${message} The key declares alg 'Ed25519', but the token uses alg 'Ed448'.`)
    )
  })

  it('rejects a key declaring EdDSA for an ES256 token', () => {
    expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk: { ...ed25519Key, alg: 'EdDSA' }, alg: 'ES256' })).toThrow(
      new JoseAlgorithmNotAllowedError(`${message} The key declares alg 'EdDSA', but the token uses alg 'ES256'.`)
    )
  })

  it('rejects a key declaring ES256 for an EdDSA token', () => {
    expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk: { ...ed25519Key, alg: 'ES256' }, alg: 'EdDSA' })).toThrow(
      new JoseAlgorithmNotAllowedError(`${message} The key declares alg 'ES256', but the token uses alg 'EdDSA'.`)
    )
  })

  it.each(['X25519', 'X448'])('rejects a key agreement key on %s for an EdDSA token', (crv) => {
    expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk: { kty: 'OKP', crv, x: 'x' }, alg: 'EdDSA' })).toThrow(
      new JoseAlgorithmNotAllowedError(
        `${message} Algorithm 'EdDSA' requires a key with crv 'Ed25519' or 'Ed448', but the key has crv '${crv}'.`
      )
    )
  })

  it('rejects an OKP key without a curve for an EdDSA token', () => {
    expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk: { kty: 'OKP', x: 'x' }, alg: 'EdDSA' })).toThrow(
      `requires a key with crv 'Ed25519' or 'Ed448', but the key has no crv`
    )
  })

  it.each([
    ['Ed25519', ed25519Key],
    ['Ed448', ed448Key],
  ])('accepts a key on %s that declares no alg for an EdDSA token', (_crv, jwk) => {
    expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk, alg: 'EdDSA' })).not.toThrow()
  })
})
