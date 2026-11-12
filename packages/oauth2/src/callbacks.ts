import type { Fetch, Openid4vcFetchType } from '@openid4vc/utils'
import type { FetchLimits, Hasher, OrPromise } from '@owf/identity-common'
import type { DecryptJweCallback, EncryptJweCallback, Jwk, JwkSet, SignJwsCallback, VerifyJwsCallback } from '@owf/jose'
import type { ClientAuthenticationCallback } from './client-authentication'
import type { AuthorizationServerMetadata } from './metadata/authorization-server/z-authorization-server-metadata'

export type {
  DecryptJweCallback,
  DecryptJweCallbackOptions,
  EncryptJweCallback,
  JweEncryptor,
  /**
   * Signs the signing input of a jws: the caller resolves the key from the signer, signs the bytes,
   * and returns the signature.
   */
  SignJwsCallback,
  /** Verifies the signature over the signing input of a jws, and decides whether the key is trusted. */
  VerifyJwsCallback,
} from '@owf/jose'
export type GenerateRandomCallback = (byteLength: number) => OrPromise<Uint8Array>

export type VerifyDataIntegrityProofCallback = (
  dataIntegrityProof: Record<string, unknown>,
  document: Record<string, unknown>
) => OrPromise<
  | {
      verified: true
      signerJwk: Jwk
    }
  | {
      verified: false
      signerJwk?: Jwk
    }
>

/**
 * Callback to resolve authorization server metadata without fetching it from the well-known
 * endpoints of the authorization server.
 *
 * The return value determines what happens next:
 * - metadata: used as-is, no request is performed.
 * - `undefined`: falls back to fetching the metadata over HTTP.
 * - `null`: the metadata definitively does not exist. No request is performed and the caller is
 *   told the metadata was not found. Return this instead of `undefined` when the callback already
 *   performed its own lookup, so the metadata is not requested a second time.
 *
 * The returned metadata is validated against the authorization server metadata schema and its
 * `issuer` MUST match the requested issuer, exactly as for fetched metadata. What the library
 * cannot check is where the metadata came from: it is used in place of the metadata that would
 * have been retrieved from the authorization server, so it MUST be at least as trustworthy. Only
 * return metadata you control (e.g. an authorization server hosted by this same application) or
 * metadata from a cache that you populated from a previous fetch for the same issuer.
 */
export type GetAuthorizationServerMetadataCallback = (
  issuer: string
) => OrPromise<AuthorizationServerMetadata | undefined | null>

/**
 * Callback to resolve a JWK Set without fetching it from the `jwks_uri`.
 *
 * Return `undefined` to fall back to fetching the JWK Set over HTTP.
 *
 * The returned JWK Set is validated against the JWK Set schema, exactly as for a fetched JWK Set.
 * What the library cannot check is where the keys came from: they are used to verify signatures in
 * place of the JWK Set that would have been fetched from `jwksUri`, so they MUST be at least as
 * trustworthy. Only return keys you control (e.g. the signing keys of an authorization server
 * hosted by this same application) or keys from a cache that you populated from a previous fetch
 * of the same `jwksUri`. Returning keys for a `jwksUri` you do not control allows arbitrary
 * signatures to be accepted.
 */
export type GetJwksCallback = (jwksUri: string) => OrPromise<JwkSet | undefined>

/**
 * Callback context provides the callbacks that are required for the openid4vc library
 */
export interface CallbackContext {
  /**
   * Custom fetch implementation to use. It gets what is requested as its third argument, `{ type }`, e.g.
   * `{ type: 'accessTokenRequest' }`.
   */
  fetch?: Fetch

  /**
   * The maximum sizes of the response bodies, per type of request. By default 10 MiB per response (see `FetchLimits`
   * of `@owf/identity-common`).
   */
  fetchLimits?: FetchLimits<Openid4vcFetchType>

  /**
   * Optional callback to resolve authorization server metadata without performing a well-known
   * request. Useful to avoid network requests for authorization servers hosted by this same
   * application, or to serve metadata from a cache.
   *
   * If not provided, or if it returns `undefined`, the metadata is fetched over HTTP.
   */
  getAuthorizationServerMetadata?: GetAuthorizationServerMetadataCallback

  /**
   * Optional callback to resolve a JWK Set without performing a request to the `jwks_uri`. Useful
   * to avoid network requests for keys held by this same application, or to serve a JWK Set from a
   * cache.
   *
   * If not provided, or if it returns `undefined`, the JWK Set is fetched over HTTP.
   */
  getJwks?: GetJwksCallback

  /**
   * Hash callback used for e.g. dpop and pkce
   */
  hash: Hasher

  /**
   * Sign jws callback, used for signing every Json Web Token this library produces.
   *
   * It signs the bytes this library computed rather than producing a token of its own, so that the
   * serialization — which is what the signature is over — is in one place.
   */
  signJws: SignJwsCallback

  /**
   * Decrypt jwe callback for decrypting of Json Web Encryptions
   */
  decryptJwe: DecryptJweCallback

  /**
   * Encrypt jwt callback for encrypting of Json Web Encryptions
   */
  encryptJwe: EncryptJweCallback

  /**
   * Verify jws callback, used for verifying every Json Web Token this library reads. Besides
   * checking the signature, this is where the caller decides whether the key is one it trusts.
   */
  verifyJws: VerifyJwsCallback

  /**
   * Verify a Data Integrity proof (e.g. the `proof` of a `di_vp` key proof's Verifiable
   * Presentation). Optional because most issuers won't support the `di_vp` proof type.
   */
  verifyDataIntegrityProof?: VerifyDataIntegrityProofCallback

  /**
   * Generate random callback to generate random bytes. Used for
   * e.g. the 'jti' value in a dpop jwt, and 'code_verifier' in pkce.
   */
  generateRandom: GenerateRandomCallback

  /**
   * Extend a request to the authorization server with client authentication
   * parameters. If you're not using client authentication, you can set this
   * to `clientAuthenticationNone()`
   *
   * There are three default client authentication methods provided:
   * - `clientAuthenticationClientSecretPost`
   * - `clientAuthenticationClientSecretBasic`
   * - `clientAuthenticationClientAttestationJwt`
   * - `clientAuthenticationNone`
   * - `clientAuthenticationAnonymous`
   *
   * A custom implementation can be made for other methods, or allowing complex
   * scenarios where multiple authorization servers are supported.
   */
  clientAuthentication: ClientAuthenticationCallback

  /**
   * Get the DNS names and URI names from a X.509 certificate
   */
  getX509CertificateMetadata?: (certificate: string) => {
    sanDnsNames: string[]
    sanUriNames: string[]
  }
}
