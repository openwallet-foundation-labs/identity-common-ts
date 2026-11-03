/**
 * Mapping between JWA and COSE algorithm identifiers. COSE identifiers are integers, so no dependency
 * on `@owf/cose` is needed.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9864 Fully-Specified Algorithms for JOSE and COSE
 */

import { JoseNotSupportedError } from '../error'
import { hasOwn } from '../utils/object'
import { JwaSignatureAlgorithm } from './algorithms'

/**
 * JWA signature algorithms to fully-specified COSE algorithms. The JOSE `ES256` is fully specified, so
 * it maps to `ESP256` (-9), not to the polymorphic COSE `ES256` (-7).
 */
const JWA_SIGNATURE_TO_COSE_ALGORITHM_MAP = {
  // EdDSA - RFC 9864 Section 2.2
  [JwaSignatureAlgorithm.Ed25519]: -19,
  [JwaSignatureAlgorithm.Ed448]: -53,

  // Deprecated polymorphic EdDSA - RFC 9864 Section 4.1.2.
  // Mapped to Ed25519 as it is by far the most common use case, as WebAuthn does.
  [JwaSignatureAlgorithm.EdDSA]: -19,

  // ECDSA - RFC 9864 Section 2.1
  [JwaSignatureAlgorithm.ES256]: -9, // ESP256
  [JwaSignatureAlgorithm.ES384]: -51, // ESP384
  [JwaSignatureAlgorithm.ES512]: -52, // ESP512
  [JwaSignatureAlgorithm.ES256K]: -47,

  // RSA - RFC 8812 and RFC 8230
  [JwaSignatureAlgorithm.RS256]: -257,
  [JwaSignatureAlgorithm.RS384]: -258,
  [JwaSignatureAlgorithm.RS512]: -259,
  [JwaSignatureAlgorithm.PS256]: -37,
  [JwaSignatureAlgorithm.PS384]: -38,
  [JwaSignatureAlgorithm.PS512]: -39,

  // HMAC - RFC 9053 Section 3.1
  [JwaSignatureAlgorithm.HS256]: 5,
  [JwaSignatureAlgorithm.HS384]: 6,
  [JwaSignatureAlgorithm.HS512]: 7,
} as const

/** The inverse of {@link JWA_SIGNATURE_TO_COSE_ALGORITHM_MAP}, plus the deprecated polymorphic COSE algorithms. */
const COSE_TO_JWA_SIGNATURE_ALGORITHM_MAP = {
  // EdDSA - RFC 9864 Section 2.2
  [-19]: JwaSignatureAlgorithm.Ed25519,
  [-53]: JwaSignatureAlgorithm.Ed448,

  // Deprecated polymorphic EdDSA - RFC 9864 Section 4.1.2 & 4.2.2
  [-8]: JwaSignatureAlgorithm.Ed25519,

  // ECDSA, fully specified - RFC 9864 Section 2.1
  [-9]: JwaSignatureAlgorithm.ES256, // ESP256
  [-51]: JwaSignatureAlgorithm.ES384, // ESP384
  [-52]: JwaSignatureAlgorithm.ES512, // ESP512
  [-47]: JwaSignatureAlgorithm.ES256K,

  // Deprecated polymorphic COSE ECDSA - RFC 9864 Section 4.2.2
  [-7]: JwaSignatureAlgorithm.ES256,
  [-35]: JwaSignatureAlgorithm.ES384,
  [-36]: JwaSignatureAlgorithm.ES512,

  // RSA
  [-257]: JwaSignatureAlgorithm.RS256,
  [-258]: JwaSignatureAlgorithm.RS384,
  [-259]: JwaSignatureAlgorithm.RS512,
  [-37]: JwaSignatureAlgorithm.PS256,
  [-38]: JwaSignatureAlgorithm.PS384,
  [-39]: JwaSignatureAlgorithm.PS512,

  // HMAC
  5: JwaSignatureAlgorithm.HS256,
  6: JwaSignatureAlgorithm.HS384,
  7: JwaSignatureAlgorithm.HS512,
} as const

export type CoseAlgorithmIdentifier = keyof typeof COSE_TO_JWA_SIGNATURE_ALGORITHM_MAP
export type JwaSignatureAlgorithmIdentifier = `${JwaSignatureAlgorithm}`

/**
 * Transforms a JWA signature algorithm identifier into an RFC 9864 fully-specified COSE algorithm
 * identifier, or `undefined` when it has no COSE counterpart.
 *
 * @example
 * ```ts
 * jwaSignatureAlgorithmToCoseAlgorithm('ES256') // -9 (ESP256)
 * ```
 */
export function jwaSignatureAlgorithmToCoseAlgorithm(jwaAlg: string): CoseAlgorithmIdentifier | undefined {
  // An own property only, so `constructor` from metadata does not resolve to `Object.prototype`
  return hasOwn(JWA_SIGNATURE_TO_COSE_ALGORITHM_MAP, jwaAlg)
    ? JWA_SIGNATURE_TO_COSE_ALGORITHM_MAP[jwaAlg as JwaSignatureAlgorithm]
    : undefined
}

/**
 * Transforms a COSE algorithm identifier — fully specified or polymorphic — into a JWA signature
 * algorithm identifier, or `undefined` when it has no JWA counterpart.
 *
 * @example
 * ```ts
 * coseAlgorithmToJwaSignatureAlgorithm(-7) // 'ES256' (from the deprecated polymorphic COSE ES256)
 * ```
 */
export function coseAlgorithmToJwaSignatureAlgorithm(coseAlg: number): JwaSignatureAlgorithmIdentifier | undefined {
  return hasOwn(COSE_TO_JWA_SIGNATURE_ALGORITHM_MAP, coseAlg)
    ? COSE_TO_JWA_SIGNATURE_ALGORITHM_MAP[coseAlg as CoseAlgorithmIdentifier]
    : undefined
}

/**
 * Transforms JWA signature algorithm identifiers into fully-specified COSE algorithm identifiers,
 * dropping the ones that have no COSE counterpart, or throwing when `throwOnUnknownValue` is set.
 */
export function jwaSignatureAlgorithmsToCoseAlgorithms(
  jwaAlgs: ReadonlyArray<string>,
  throwOnUnknownValue = false
): CoseAlgorithmIdentifier[] {
  return jwaAlgs
    .map((jwaAlg) => {
      const coseAlg = jwaSignatureAlgorithmToCoseAlgorithm(jwaAlg)
      if (coseAlg || !throwOnUnknownValue) return coseAlg
      throw new JoseNotSupportedError(`Found unknown JWA signature algorithm '${jwaAlg}'. Unable to map to COSE.`)
    })
    .filter((coseAlg): coseAlg is CoseAlgorithmIdentifier => coseAlg !== undefined)
}

/**
 * Transforms COSE algorithm identifiers into JWA signature algorithm identifiers, dropping the ones
 * that have no JWA counterpart, or throwing when `throwOnUnknownValue` is set.
 */
export function coseAlgorithmsToJwaSignatureAlgorithms(
  coseAlgs: ReadonlyArray<number>,
  throwOnUnknownValue = false
): JwaSignatureAlgorithmIdentifier[] {
  return coseAlgs
    .map((coseAlg) => {
      const jwaAlg = coseAlgorithmToJwaSignatureAlgorithm(coseAlg)
      if (jwaAlg || !throwOnUnknownValue) return jwaAlg
      throw new JoseNotSupportedError(`Found unknown COSE algorithm identifier '${coseAlg}'. Unable to map to JWA.`)
    })
    .filter((jwaAlg): jwaAlg is JwaSignatureAlgorithmIdentifier => jwaAlg !== undefined)
}
