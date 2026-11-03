import type { Hasher } from '@owf/identity-common'
import { JoseSignerError } from '../error'
import { isSameJsonValue } from '../utils/object'
import { calculateJwkThumbprint, zJwkThumbprintComponents } from './thumbprint'
import type { Jwk, JwkSet } from './z-jwk'

export interface ExtractJwkFromJwkSetOptions {
  /** The JWK Set to select a key from. */
  jwks: JwkSet

  /** The `kid` of the key to select, typically taken from the header of the token to verify. */
  kid?: string

  /** Whether the key is used for signature verification or for encryption. */
  use: 'enc' | 'sig'
}

/**
 * The key when every one of `jwks` is the same JWK, and `undefined` when they differ or there are none.
 *
 * The same JWK listed twice is one candidate rather than an ambiguity. Two JWKs for the same key that
 * differ in another member — the `alg` they declare, say — are not: which of them is selected decides
 * what the key is checked against.
 */
const onlyJwk = (jwks: ReadonlyArray<Jwk>): Jwk | undefined => {
  const [first, ...rest] = jwks
  return first && rest.every((jwk) => isSameJsonValue(jwk, first)) ? first : undefined
}

/**
 * Selects the key to use from a JWK Set: the key with the given `kid`, or the only key that is
 * usable for `use` when no `kid` was given.
 *
 * Keys that declare a different `use` are never selected, and a set with more than one candidate is
 * an error rather than a guess, since picking the wrong key silently would mean verifying against a
 * key the issuer did not sign with. That includes a `kid` that more than one key in the set has, as
 * during a key rotation. A set that lists the same JWK twice has one candidate.
 *
 * @throws JoseSignerError if no key, or more than one, is a candidate.
 */
export function extractJwkFromJwkSet(options: ExtractJwkFromJwkSetOptions): Jwk {
  const jwksForUse = options.jwks.keys.filter(({ use }) => !use || use === options.use)

  if (options.kid) {
    const jwksForKid = jwksForUse.filter(({ kid }) => kid === options.kid)
    if (jwksForKid.length === 0) {
      throw new JoseSignerError(
        `Unable to extract jwk from jwks for use '${options.use}'. No key with kid '${options.kid}' found.`
      )
    }

    const jwkForKid = onlyJwk(jwksForKid)
    if (jwkForKid) return jwkForKid

    throw new JoseSignerError(
      `Unable to extract jwk from jwks for use '${options.use}'. The jwks contains ${jwksForKid.length} keys with kid '${options.kid}' that differ, and it is ambiguous which one applies.`
    )
  }

  const jwkForUse = onlyJwk(jwksForUse)
  if (jwkForUse) return jwkForUse

  throw new JoseSignerError(
    `Unable to extract jwk from jwks for use '${options.use}'. No kid provided and the jwks contains ${jwksForUse.length} keys for this use.`
  )
}

/**
 * Whether `jwk` is one of `jwks`, compared by JWK thumbprint so that two representations of the same
 * key — differing in member order, or in optional members such as `kid` or `alg` — still match.
 *
 * A key in the set whose thumbprint cannot be computed — a key type RFC 7638 names no members for,
 * such as an ML-DSA `AKP` key, or a key missing one of the members — cannot be `jwk`, whose thumbprint
 * can. It is skipped rather than failing the lookup, so that the outcome does not depend on where in
 * the set it is.
 *
 * @throws JoseValidationError if the thumbprint of `jwk` itself cannot be computed.
 */
export async function isJwkInSet({
  jwk,
  jwks,
  hashCallback,
}: {
  jwk: Jwk
  jwks: ReadonlyArray<Jwk>
  hashCallback: Hasher
}): Promise<boolean> {
  const thumbprint = await calculateJwkThumbprint({ jwk, hashAlgorithm: 'sha-256', hashCallback })

  for (const jwkFromSet of jwks) {
    if (!zJwkThumbprintComponents.safeParse(jwkFromSet).success) continue

    const thumbprintFromSet = await calculateJwkThumbprint({
      jwk: jwkFromSet,
      hashAlgorithm: 'sha-256',
      hashCallback,
    })

    if (thumbprintFromSet === thumbprint) return true
  }

  return false
}
