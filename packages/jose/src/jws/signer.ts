import { JoseSignerError } from '../error'
import type { Jwk } from '../jwk/z-jwk'
import type { JwsProtectedHeader } from './z-jws'

/** The signer is identified by a DID URL, resolved to a verification method by the caller. */
export type JwsSignerDid = {
  method: 'did'
  didUrl: string
  alg: string

  /** The key id to sign with. It must match the key of `didUrl`. */
  kid?: string
}

/** The signer is identified by a public JWK, carried in the `jwk` header parameter. */
export type JwsSignerJwk = {
  method: 'jwk'
  publicJwk: Jwk
  alg: string

  /** The key id to sign with. It must match `publicJwk`, and is not added to the header. */
  kid?: string
}

/** The signer is identified by an X.509 certificate chain, carried in the `x5c` header parameter. */
export type JwsSignerX5c = {
  method: 'x5c'
  x5c: string[]
  alg: string

  /** The key id to sign with. It must match the key of the leaf certificate. */
  kid?: string
}

/** The signer is established through an OpenID Federation trust chain. */
export type JwsSignerFederation = {
  method: 'federation'
  trustChain?: [string, ...string[]]
  alg: string

  /** The key id to sign with. It must match a key in the federation. */
  kid: string
}

/** The signer is established out of band. */
export type JwsSignerCustom = {
  method: 'custom'
  alg: string

  /** The key id that should be used for signing. Added to the header as `kid`. */
  kid?: string
}

export type JwsSigner = JwsSignerDid | JwsSignerJwk | JwsSignerX5c | JwsSignerFederation | JwsSignerCustom

export type JwsSignerMethod = JwsSigner['method']

/** A {@link JwsSigner} whose public key is known, which is what verification establishes. */
export type JwsSignerWithJwk = JwsSigner & { publicJwk: Jwk }

/**
 * The header parameters that identify the signer, as derived from a {@link JwsSigner}:
 *
 * - `did`: the DID URL, as `kid`.
 * - `federation`: `kid` and `trust_chain`. Without a trust chain that is `kid` alone, from which a
 *   verifier establishes a `custom` signer.
 * - `jwk`: `jwk`. The `kid` of the signer is not added.
 * - `x5c`: `x5c`. The `kid` of the signer is not added.
 * - `custom`: `kid`, when the signer has one.
 */
export function jwsHeaderFromSigner(signer: JwsSigner) {
  if (signer.method === 'did') {
    return { alg: signer.alg, kid: signer.didUrl } as const
  }

  if (signer.method === 'federation') {
    return { alg: signer.alg, kid: signer.kid, trust_chain: signer.trustChain } as const
  }

  if (signer.method === 'jwk') {
    return { alg: signer.alg, jwk: signer.publicJwk } as const
  }

  if (signer.method === 'x5c') {
    return { alg: signer.alg, x5c: signer.x5c } as const
  }

  return signer.kid !== undefined ? ({ alg: signer.alg, kid: signer.kid } as const) : ({ alg: signer.alg } as const)
}

export interface JwsSignerFromHeaderOptions {
  /** The protected header of the JWS. */
  header: JwsProtectedHeader

  /** The `iss` of a JWT, as a DID signer can be a DID in `iss` with a fragment in `kid`. */
  issuer?: string

  /** The signer methods the caller accepts. */
  allowedSignerMethods?: ReadonlyArray<JwsSignerMethod>

  /**
   * Whether to accept a header that identifies the signer in more than one way, taking the first allowed
   * of `x5c`, `trust_chain`, `did` and `jwk`. Off by default, so a trusted `x5c` next to an attacker's
   * `jwk` is rejected rather than resolved by precedence.
   *
   * @default false
   */
  allowMultipleSignerMethods?: boolean

  /**
   * Whether the DID in `kid` may differ from `iss`, as in `openid4vci-proof+jwt`, where `iss` is the
   * client id.
   *
   * @default false
   */
  allowDidKidIssuerMismatch?: boolean
}

type FoundSigner =
  | { method: JwsSignerMethod; signer: JwsSigner; valid: true }
  | { method: JwsSignerMethod; error: string; valid: false }

/**
 * The DID a DID URL refers to: everything before its path, query or fragment.
 *
 * @see https://www.w3.org/TR/did-core/#did-url-syntax
 */
const didOfDidUrl = (didUrl: string): string => {
  const end = didUrl.search(/[/?#]/)
  return end === -1 ? didUrl : didUrl.slice(0, end)
}

/**
 * Establishes the signer of a JWS from its header. Whether the key is trusted is for the verification
 * callback.
 *
 * @throws JoseSignerError if the signer cannot be established, or is identified in more than one way.
 */
export function jwsSignerFromHeader({
  header,
  issuer,
  allowedSignerMethods,
  allowMultipleSignerMethods = false,
  allowDidKidIssuerMismatch = false,
}: JwsSignerFromHeaderOptions): JwsSigner {
  const found: FoundSigner[] = []

  if (header.x5c) {
    found.push({
      method: 'x5c',
      valid: true,
      signer: { method: 'x5c', alg: header.alg, x5c: header.x5c, kid: header.kid },
    })
  }

  if (header.trust_chain) {
    if (!header.kid) {
      found.push({
        method: 'federation',
        valid: false,
        error: `When 'trust_chain' is used in the header, the 'kid' parameter is required.`,
      })
    } else {
      found.push({
        method: 'federation',
        valid: true,
        signer: { method: 'federation', alg: header.alg, trustChain: header.trust_chain, kid: header.kid },
      })
    }
  }

  if (header.kid?.startsWith('did:') || issuer?.startsWith('did:')) {
    // An exact match: `did:web:example.com.evil.org` starts with `did:web:example.com`
    if (issuer && header.kid?.startsWith('did:') && didOfDidUrl(header.kid) !== issuer && !allowDidKidIssuerMismatch) {
      found.push({
        method: 'did',
        valid: false,
        error: `kid in header starts with a did that is different from the did value in 'iss'`,
      })
    } else if (!header.kid?.startsWith('did:') && !header.kid?.startsWith('#')) {
      found.push({
        method: 'did',
        valid: false,
        error: `kid in header must start with either 'did:' or '#' when the 'iss' value is a did`,
      })
    } else {
      found.push({
        method: 'did',
        valid: true,
        signer: {
          method: 'did',
          alg: header.alg,
          didUrl: header.kid.startsWith('did:') ? header.kid : `${issuer}${header.kid}`,
        },
      })
    }
  }

  if (header.jwk) {
    found.push({
      method: 'jwk',
      valid: true,
      signer: { method: 'jwk', alg: header.alg, publicJwk: header.jwk },
    })
  }

  const allowedFound = found.filter((f) => !allowedSignerMethods || allowedSignerMethods.includes(f.method))
  const allowedValid = allowedFound.filter((f) => f.valid)

  if (allowedValid.length > 1 && !allowMultipleSignerMethods) {
    throw new JoseSignerError(
      `Unable to establish the signer of the JWS. The header identifies the signer in ${allowedValid.length} ways (${allowedValid
        .map((f) => `'${f.method}'`)
        .join(
          ', '
        )}), and it is ambiguous which one applies. Narrow it down with 'allowedSignerMethods', or set 'allowMultipleSignerMethods'.`
    )
  }

  if (allowedValid.length > 0) return allowedValid[0].signer

  if (allowedFound.length > 0) {
    throw new JoseSignerError(
      `Unable to establish the signer of the JWS. Found ${allowedFound.length} allowed signer method(s), but they contained an invalid configuration:\n${allowedFound
        .map((f) => (f.valid ? '' : `FAILED: method ${f.method} - ${f.error}`))
        .join('\n')}`
    )
  }

  if (found.length > 0) {
    throw new JoseSignerError(
      `Unable to establish the signer of the JWS. Found ${found.length} signer method(s) that are not allowed:\n${found
        .map((f) => (f.valid ? `SUCCEEDED: method ${f.method}` : `FAILED: method ${f.method} - ${f.error}`))
        .join('\n')}`
    )
  }

  if (!allowedSignerMethods || allowedSignerMethods.includes('custom')) {
    return { method: 'custom', alg: header.alg, kid: header.kid }
  }

  throw new JoseSignerError(
    `Unable to establish the signer of the JWS. The header identifies no signer method, and the 'custom' signer method is not allowed.`
  )
}
