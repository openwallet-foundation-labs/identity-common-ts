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
 * The JWK when every one of `jwks` is the same, otherwise `undefined`. Two JWKs of one key that differ
 * in e.g. `alg` are ambiguous, as the selected one decides what the key is checked against.
 */
const onlyJwk = (jwks: ReadonlyArray<Jwk>): Jwk | undefined => {
  const [first, ...rest] = jwks
  return first && rest.every((jwk) => isSameJsonValue(jwk, first)) ? first : undefined
}

/**
 * Selects the key with `kid` from a JWK Set, or the only key for `use` without a `kid`. Keys with
 * another `use` are skipped. More than one candidate, as during a key rotation, throws.
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
 * Whether `jwk` is one of `jwks`, compared by JWK thumbprint. Keys in the set without a thumbprint,
 * such as an ML-DSA `AKP` key, are skipped.
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
