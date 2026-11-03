import { JoseAlgorithmNotAllowedError } from '../error'
import type { Jwk } from '../jwk/z-jwk'
import {
  isJwaSignatureAlgorithm,
  isJwaSignatureAlgorithmCaseVariant,
  JwaSignatureAlgorithm,
  signatureAlgorithmCurves,
  signatureAlgorithmKeyTypes,
} from './algorithms'

/** `EdDSA` with the curve fixed (RFC 9864 section 2.2). */
const fullySpecifiedEdDsaAlgorithms: ReadonlyArray<string> = [
  JwaSignatureAlgorithm.Ed25519,
  JwaSignatureAlgorithm.Ed448,
]

/** The curves of `EdDSA` (RFC 8037 section 3.1). `X25519` and `X448` are for key agreement. */
const edDsaCurves: ReadonlyArray<string> = ['Ed25519', 'Ed448']

/**
 * Checks that a key can be used with a signature algorithm, as the token chooses its `alg` but not the
 * key: the key type (no key confusion), the curve where the algorithm fixes one, and the `alg`, `use`
 * and `key_ops` the key declares. `EdDSA` and `Ed25519`/`Ed448` (RFC 9864) count as the same `alg`.
 * An unregistered algorithm is left to the verification callback, but one that differs from a
 * registered algorithm only in casing is rejected.
 *
 * @throws JoseAlgorithmNotAllowedError when the key cannot be used with the algorithm.
 */
export function assertKeyAllowedForSignatureAlgorithm({
  jwk,
  alg,
  errorMessage = 'Unable to use the key with the algorithm of the token.',
}: {
  jwk: Jwk
  alg: string
  errorMessage?: string
}): void {
  const isEdDsaEquivalent =
    (jwk.alg === JwaSignatureAlgorithm.EdDSA && fullySpecifiedEdDsaAlgorithms.includes(alg)) ||
    (alg === JwaSignatureAlgorithm.EdDSA && jwk.alg !== undefined && fullySpecifiedEdDsaAlgorithms.includes(jwk.alg))

  if (jwk.alg !== undefined && jwk.alg !== alg && !isEdDsaEquivalent) {
    throw new JoseAlgorithmNotAllowedError(
      `${errorMessage} The key declares alg '${jwk.alg}', but the token uses alg '${alg}'.`
    )
  }

  if (jwk.use !== undefined && jwk.use !== 'sig') {
    throw new JoseAlgorithmNotAllowedError(`${errorMessage} The key declares use '${jwk.use}' instead of 'sig'.`)
  }

  if (jwk.key_ops !== undefined && !jwk.key_ops.includes('verify') && !jwk.key_ops.includes('sign')) {
    throw new JoseAlgorithmNotAllowedError(
      `${errorMessage} The key declares key_ops ${jwk.key_ops.map((op) => `'${op}'`).join(', ')}, which does not include 'sign' or 'verify'.`
    )
  }

  if (isJwaSignatureAlgorithmCaseVariant(alg)) {
    throw new JoseAlgorithmNotAllowedError(
      `${errorMessage} The token uses alg '${alg}', which differs from a registered algorithm only in casing.`
    )
  }

  if (!isJwaSignatureAlgorithm(alg)) return

  // For a token that only says `EdDSA`, the fully specified algorithm the key declares fixes the curve
  const keyAlgorithm =
    isEdDsaEquivalent && alg === JwaSignatureAlgorithm.EdDSA ? (jwk.alg as JwaSignatureAlgorithm) : alg

  const keyTypes = signatureAlgorithmKeyTypes[keyAlgorithm]
  if (!keyTypes.includes(jwk.kty)) {
    throw new JoseAlgorithmNotAllowedError(
      `${errorMessage} Algorithm '${keyAlgorithm}' requires a key with kty ${keyTypes.map((kty) => `'${kty}'`).join(' or ')}, but the key has kty '${jwk.kty}'.`
    )
  }

  const curve = signatureAlgorithmCurves[keyAlgorithm]
  const curves = curve !== undefined ? [curve] : keyAlgorithm === JwaSignatureAlgorithm.EdDSA ? edDsaCurves : []
  if (curves.length > 0 && (jwk.crv === undefined || !curves.includes(jwk.crv))) {
    throw new JoseAlgorithmNotAllowedError(
      `${errorMessage} Algorithm '${keyAlgorithm}' requires a key with crv ${curves.map((crv) => `'${crv}'`).join(' or ')}, but the key has ${jwk.crv ? `crv '${jwk.crv}'` : 'no crv'}.`
    )
  }
}
