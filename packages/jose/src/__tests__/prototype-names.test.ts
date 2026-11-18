import { base64url, stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { JoseNotSupportedError } from '../error'
import {
  coseAlgorithmsToJwaSignatureAlgorithms,
  coseAlgorithmToJwaSignatureAlgorithm,
  jwaSignatureAlgorithmsToCoseAlgorithms,
  jwaSignatureAlgorithmToCoseAlgorithm,
} from '../jwa/cose-algorithm'
import { parseJws } from '../jws/parse-jws'
import { verifyJwtClaims } from '../jwt/verify-jwt-claims'
import { claimIssue, unsignedCompactJws } from './context'

/**
 * Names such as `constructor` and `toString` are properties of every object through its prototype.
 * A header parameter, claim or algorithm with such a name is only present when the object itself has
 * it.
 */
const inheritedNames = ['constructor', 'toString', 'hasOwnProperty', '__proto__']

const encode = (value: unknown) => base64url.encode(stringToBytes(JSON.stringify(value)))

describe('header parameters named after Object.prototype members', () => {
  const payload = encode({ iss: 'https://issuer.example' })

  it.each(['toString', 'constructor'])('accepts an unprotected header parameter named %s', (name) => {
    const parsed = parseJws({
      jws: { protected: encode({ alg: 'ES256' }), header: { [name]: 'x' }, payload, signature: 'c2ln' },
    })

    expect(parsed.unprotectedHeader).toEqual({ [name]: 'x' })
  })

  it.each(['constructor', 'toString'])('rejects a crit that lists %s when the header does not contain it', (name) => {
    const jws = unsignedCompactJws({ alg: 'ES256', crit: [name] }, {})

    expect(() => parseJws({ jws, understoodCriticalParameters: [name] })).toThrow(
      expect.objectContaining({
        issues: [
          expect.objectContaining({
            code: 'invalid_crit',
            path: ['crit', 0],
            message: `The 'crit' header parameter lists '${name}', but the header does not contain that parameter`,
          }),
        ],
      })
    )
  })

  it('accepts a crit that lists a parameter named toString carried in the unprotected header', () => {
    const parsed = parseJws({
      jws: {
        protected: encode({ alg: 'ES256', crit: ['toString'] }),
        header: { toString: 'x' },
        payload,
        signature: 'c2ln',
      },
      understoodCriticalParameters: ['toString'],
    })

    expect(parsed.protectedHeader.crit).toEqual(['toString'])
  })
})

describe('required claims named after Object.prototype members', () => {
  it.each(['constructor', 'toString'])('rejects a token without a required %s claim', (claim) => {
    expect(() => verifyJwtClaims({}, { requiredClaims: [claim] })).toThrow(claimIssue(claim, 'claim_missing'))
  })

  it('accepts a required claim the token carries as an own property', () => {
    expect(() => verifyJwtClaims({ toString: 'x' }, { requiredClaims: ['toString'] })).not.toThrow()
  })
})

describe('mapping algorithm names named after Object.prototype members', () => {
  it.each(inheritedNames)('maps the JWA algorithm %s to no COSE algorithm', (name) => {
    expect(jwaSignatureAlgorithmToCoseAlgorithm(name)).toBeUndefined()
  })

  it('drops JWA algorithms named after Object.prototype members from a list', () => {
    expect(jwaSignatureAlgorithmsToCoseAlgorithms(['ES256', ...inheritedNames])).toEqual([-9])
  })

  it.each(inheritedNames)('throws for the JWA algorithm %s when unknown values are not allowed', (name) => {
    expect(() => jwaSignatureAlgorithmsToCoseAlgorithms(['ES256', name], true)).toThrow(
      new JoseNotSupportedError(`Found unknown JWA signature algorithm '${name}'. Unable to map to COSE.`)
    )
  })

  it.each(inheritedNames)('maps the COSE algorithm %s to no JWA algorithm', (name) => {
    // Only reachable without types, as the COSE identifiers are numbers
    expect(coseAlgorithmToJwaSignatureAlgorithm(name as unknown as number)).toBeUndefined()
  })

  it('throws for a COSE algorithm named after an Object.prototype member when unknown values are not allowed', () => {
    expect(() => coseAlgorithmsToJwaSignatureAlgorithms([-9, 'constructor' as unknown as number], true)).toThrow(
      JoseNotSupportedError
    )
  })
})
