/**
 * @owf/jose
 *
 * JOSE (JWK, JWA and JWS) with strict, schema based parsing and verification.
 *
 * Everything is built on two ideas:
 *
 * 1. Encoding is handled in one place. Every base64url, UTF-8 and JSON decode goes through
 *    `@owf/identity-common`, which rejects anything that is not exactly what it claims to be instead
 *    of decoding it into something close.
 * 2. A token type is expressed as a schema, not as a class. Compose the schemas exported here to say
 *    what a token must look like, and everything that follows from the token alone is then checked
 *    when it is parsed. What cannot be checked that way — which algorithms and signers to accept —
 *    is passed to the verification functions.
 *
 * @packageDocumentation
 */

export * from './callbacks'
export * from './error'
export * from './jwa/algorithms'
export * from './jwa/cose-algorithm'
export * from './jwa/key-compatibility'
export * from './jwa/z-alg'
export * from './jwk/jwks'
export * from './jwk/thumbprint'
export * from './jwk/z-jwk'
export * from './jwk/z-x5c'
export * from './jws/critical-headers'
export * from './jws/parse-jws'
export * from './jws/sign-jws'
export * from './jws/signer'
export * from './jws/verify-jws'
export * from './jws/z-jws'
export { decodeBase64UrlBytes, decodeBase64UrlJsonObject, encodeBase64UrlJson } from './utils/encoding'
export { zStringOrUri } from './utils/z-common'
export type { InferSchemaOrDefaultOutput } from './utils/zod'
