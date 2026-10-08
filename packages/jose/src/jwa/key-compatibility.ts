import { JoseAlgorithmNotAllowedError } from '../error'
import type { Jwk } from '../jwk/z-jwk'
import {
  isJwaSignatureAlgorithm,
  isJwaSignatureAlgorithmCaseVariant,
  JwaSignatureAlgorithm,
  signatureAlgorithmCurves,
  signatureAlgorithmKeyTypes,
} from './algorithms'

/**
 * The algorithms RFC 9864 defines in place of the polymorphic `EdDSA`: the same signature algorithm,
 * with the curve fixed.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9864#section-2.2
 */
const fullySpecifiedEdDsaAlgorithms: ReadonlyArray<string> = [
  JwaSignatureAlgorithm.Ed25519,
  JwaSignatureAlgorithm.Ed448,
]

/**
 * The curves `EdDSA` is defined for. It is polymorphic, so it does not fix one of them, but an `OKP`
 * key on `X25519` or `X448` is a key agreement key rather than a signing key.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8037#section-3.1
 */
const edDsaCurves: ReadonlyArray<string> = ['Ed25519', 'Ed448']

/**
 * Checks that a key can be used with a signature algorithm, and that the key does not say it is for
 * something else.
 *
 * Three things are checked, all of them for the same reason — the `alg` of a token is chosen by
 * whoever wrote the token, and the key is not:
 *
 * 1. The key type matches the algorithm family, which is what rules out key confusion: a token
 *    signed with `HS256` over a public RSA key is a valid MAC to anybody who has that public key.
 * 2. The curve matches, for the algorithms that fully specify one. `EdDSA` does not, but still
 *    requires one of the curves it is defined for.
 * 3. The `alg` and `use` the key itself declares are not contradicted. `EdDSA` and its fully
 *    specified forms `Ed25519` and `Ed448` (RFC 9864) do not contradict each other: a key declaring
 *    one of them can be used for a token declaring the other, on the curve the fully specified name
 *    requires.
 *
 * An unregistered algorithm is not rejected: the JWA registry is open, and an algorithm this package
 * does not know about is a matter for the verification callback. It only means there is nothing to
 * check here. A registered algorithm in a different casing (`hs256`) is rejected, as nothing could be
 * checked for what it would be taken for downstream.
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
