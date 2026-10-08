import type { OrPromise } from '@owf/identity-common'

/**
 * The hash algorithms used by the JOSE structures in this package, named as in the IANA Named
 * Information registry so the values line up with the `HashAlgorithm` type of `@owf/identity-common`.
 *
 * @see https://www.iana.org/assignments/named-information/named-information.xhtml
 */
export enum HashAlgorithm {
  Sha256 = 'sha-256',
  Sha384 = 'sha-384',
  Sha512 = 'sha-512',
}

/**
 * Callback used for operations that require hashing, such as computing a JWK thumbprint.
 *
 * Hashing is provided by the caller rather than taken from a global, so that this package does not
 * depend on a crypto implementation being present in the environment.
 */
export type HashCallback = (data: Uint8Array, alg: HashAlgorithm) => OrPromise<Uint8Array>
