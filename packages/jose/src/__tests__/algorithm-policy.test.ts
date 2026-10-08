import { describe, expect, it } from 'vitest'
import { JoseAlgorithmNotAllowedError } from '../error'
import { isJwaSignatureAlgorithmCaseVariant } from '../jwa/algorithms'
import { assertKeyAllowedForSignatureAlgorithm } from '../jwa/key-compatibility'
import { parseJws } from '../jws/parse-jws'
import { assertJwsAlgorithmAllowed, verifyJwsSignature } from '../jws/verify-jws'
import { verifyJwt } from '../jwt/verify-jwt'
import { unsignedCompactJws } from './context'

const rsaJwk = { kty: 'RSA', n: 'n', e: 'AQAB' }
const verifiedWithRsaKey = () => ({ verified: true as const, signerJwk: rsaJwk })

describe("alg 'none' in the algorithm policy", () => {
  it.each(['none', 'None', 'NONE', 'nOnE'])("rejects '%s'", (alg) => {
    expect(() => assertJwsAlgorithmAllowed({ alg })).toThrow(
      new JoseAlgorithmNotAllowedError(
        `Error during verification of the JWS. The JWS uses alg '${alg}', which is not a signature algorithm. An unsecured JWS is never accepted.`
      )
    )
  })

  it("rejects 'none' even when the caller lists it as allowed", () => {
    expect(() => assertJwsAlgorithmAllowed({ alg: 'none', allowedAlgorithms: ['none'] })).toThrow(
      JoseAlgorithmNotAllowedError
    )
  })

  it('rejects an empty alg', () => {
    expect(() => assertJwsAlgorithmAllowed({ alg: '' })).toThrow(JoseAlgorithmNotAllowedError)
  })

  it('rejects a missing alg', () => {
    expect(() => assertJwsAlgorithmAllowed({ alg: undefined as unknown as string })).toThrow(
      JoseAlgorithmNotAllowedError
    )
  })
})

/**
 * Algorithm names are case-sensitive, so `hs256` is not `HS256` and the checks keyed on the
 * registered names do not recognize it. A callback that compares names ignoring casing would then
 * verify it as `HS256` with a key that was never checked against it.
 */
describe('algorithms that differ from a registered algorithm only in casing', () => {
  it.each(['hs256', 'Hs256', 'hS512', 'es256', 'Es256', 'eddsa', 'ES256k'])("rejects '%s'", (alg) => {
    expect(() => assertJwsAlgorithmAllowed({ alg })).toThrow(
      new JoseAlgorithmNotAllowedError(
        `Error during verification of the JWS. The JWS uses alg '${alg}', which differs from a registered algorithm only in casing. Algorithm names are case-sensitive.`
      )
    )
  })

  it('rejects a case variant of a symmetric algorithm when symmetric algorithms are allowed', () => {
    expect(() => assertJwsAlgorithmAllowed({ alg: 'hs256', allowSymmetricAlgorithms: true })).toThrow(
      'differs from a registered algorithm only in casing'
    )
  })

  it('rejects a case variant the caller lists as allowed', () => {
    expect(() =>
      assertJwsAlgorithmAllowed({ alg: 'hs256', allowedAlgorithms: ['hs256'], allowSymmetricAlgorithms: true })
    ).toThrow('differs from a registered algorithm only in casing')
  })

  it('rejects a variant that only matches a registered algorithm when both are upper cased', () => {
    // 'ſ' (U+017F, long s) upper cases to 'S'
    expect(() => assertJwsAlgorithmAllowed({ alg: 'hſ256' })).toThrow(
      'differs from a registered algorithm only in casing'
    )
  })

  it('accepts an algorithm this package does not know', () => {
    expect(() => assertJwsAlgorithmAllowed({ alg: 'ML-DSA-44' })).not.toThrow()
  })

  it.each([false, true])(
    'rejects a JWS with alg hs256 verified with an RSA key, with allowSymmetricAlgorithms %s',
    async (allowSymmetricAlgorithms) => {
      const jws = parseJws({ jws: unsignedCompactJws({ alg: 'hs256' }, {}) })

      await expect(
        verifyJwsSignature({ jws, verifyJwsCallback: verifiedWithRsaKey, allowSymmetricAlgorithms })
      ).rejects.toThrow(JoseAlgorithmNotAllowedError)
    }
  )

  it('rejects a JWT with alg Hs256 verified with an RSA key', async () => {
    const jwt = unsignedCompactJws({ alg: 'Hs256' }, { iss: 'https://issuer.example' })

    await expect(verifyJwt({ jwt, verifyJwsCallback: verifiedWithRsaKey })).rejects.toThrow(
      'differs from a registered algorithm only in casing'
    )
  })

  it('does not take a value that is not a string for a case variant', () => {
    expect(isJwaSignatureAlgorithmCaseVariant(256 as unknown as string)).toBe(false)
  })

  it('rejects a key checked against a case variant of a registered algorithm', () => {
    expect(() => assertKeyAllowedForSignatureAlgorithm({ jwk: rsaJwk, alg: 'hs256' })).toThrow(
      new JoseAlgorithmNotAllowedError(
        `Unable to use the key with the algorithm of the token. The token uses alg 'hs256', which differs from a registered algorithm only in casing.`
      )
    )
  })
})
