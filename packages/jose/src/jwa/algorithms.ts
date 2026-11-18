/**
 * JWA (JSON Web Algorithms) identifiers.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518
 * @see https://www.iana.org/assignments/jose/jose.xhtml
 */

/**
 * JWS signature and MAC algorithms. `none` is absent: an unsecured JWS is never accepted.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-3.1
 * @see https://www.rfc-editor.org/rfc/rfc9864 for the fully-specified EdDSA algorithms
 */
export enum JwaSignatureAlgorithm {
  // HMAC with SHA-2
  HS256 = 'HS256',
  HS384 = 'HS384',
  HS512 = 'HS512',

  // RSASSA-PKCS1-v1_5 with SHA-2
  RS256 = 'RS256',
  RS384 = 'RS384',
  RS512 = 'RS512',

  // RSASSA-PSS with SHA-2
  PS256 = 'PS256',
  PS384 = 'PS384',
  PS512 = 'PS512',

  // ECDSA
  ES256 = 'ES256',
  ES384 = 'ES384',
  ES512 = 'ES512',
  ES256K = 'ES256K',

  // EdDSA. `EdDSA` is polymorphic and deprecated by RFC 9864 in favour of the curve-specific names.
  EdDSA = 'EdDSA',
  Ed25519 = 'Ed25519',
  Ed448 = 'Ed448',
}

/** The signature algorithms with a symmetric key, with which every verifier can also issue a token. */
export const symmetricSignatureAlgorithms = [
  JwaSignatureAlgorithm.HS256,
  JwaSignatureAlgorithm.HS384,
  JwaSignatureAlgorithm.HS512,
] as const satisfies ReadonlyArray<JwaSignatureAlgorithm>

/**
 * JWE key management algorithms.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-4.1
 */
export enum JwaKeyManagementAlgorithm {
  RSA1_5 = 'RSA1_5',
  RSA_OAEP = 'RSA-OAEP',
  RSA_OAEP_256 = 'RSA-OAEP-256',
  A128KW = 'A128KW',
  A192KW = 'A192KW',
  A256KW = 'A256KW',
  Dir = 'dir',
  ECDH_ES = 'ECDH-ES',
  ECDH_ES_A128KW = 'ECDH-ES+A128KW',
  ECDH_ES_A192KW = 'ECDH-ES+A192KW',
  ECDH_ES_A256KW = 'ECDH-ES+A256KW',
  A128GCMKW = 'A128GCMKW',
  A192GCMKW = 'A192GCMKW',
  A256GCMKW = 'A256GCMKW',
}

/**
 * JWE content encryption algorithms.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-5.1
 */
export enum JwaContentEncryptionAlgorithm {
  A128CBC_HS256 = 'A128CBC-HS256',
  A192CBC_HS384 = 'A192CBC-HS384',
  A256CBC_HS512 = 'A256CBC-HS512',
  A128GCM = 'A128GCM',
  A192GCM = 'A192GCM',
  A256GCM = 'A256GCM',
}

/**
 * The key types (`kty`) a signature algorithm can be used with. Checking it prevents key confusion,
 * such as `HS256` with an RSA public key as the MAC secret.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-3.1
 * @see https://www.rfc-editor.org/rfc/rfc8725#section-3.5
 */
export const signatureAlgorithmKeyTypes: Record<JwaSignatureAlgorithm, ReadonlyArray<string>> = {
  [JwaSignatureAlgorithm.HS256]: ['oct'],
  [JwaSignatureAlgorithm.HS384]: ['oct'],
  [JwaSignatureAlgorithm.HS512]: ['oct'],

  [JwaSignatureAlgorithm.RS256]: ['RSA'],
  [JwaSignatureAlgorithm.RS384]: ['RSA'],
  [JwaSignatureAlgorithm.RS512]: ['RSA'],
  [JwaSignatureAlgorithm.PS256]: ['RSA'],
  [JwaSignatureAlgorithm.PS384]: ['RSA'],
  [JwaSignatureAlgorithm.PS512]: ['RSA'],

  [JwaSignatureAlgorithm.ES256]: ['EC'],
  [JwaSignatureAlgorithm.ES384]: ['EC'],
  [JwaSignatureAlgorithm.ES512]: ['EC'],
  [JwaSignatureAlgorithm.ES256K]: ['EC'],

  [JwaSignatureAlgorithm.EdDSA]: ['OKP'],
  [JwaSignatureAlgorithm.Ed25519]: ['OKP'],
  [JwaSignatureAlgorithm.Ed448]: ['OKP'],
}

/**
 * The curve (`crv`) of the signature algorithms that fully specify one. `EdDSA` is polymorphic.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-3.4
 * @see https://www.rfc-editor.org/rfc/rfc9864#section-2
 */
export const signatureAlgorithmCurves: Partial<Record<JwaSignatureAlgorithm, string>> = {
  [JwaSignatureAlgorithm.ES256]: 'P-256',
  [JwaSignatureAlgorithm.ES384]: 'P-384',
  [JwaSignatureAlgorithm.ES512]: 'P-521',
  [JwaSignatureAlgorithm.ES256K]: 'secp256k1',
  [JwaSignatureAlgorithm.Ed25519]: 'Ed25519',
  [JwaSignatureAlgorithm.Ed448]: 'Ed448',
}

export const isJwaSignatureAlgorithm = (alg: string): alg is JwaSignatureAlgorithm =>
  Object.values(JwaSignatureAlgorithm).includes(alg as JwaSignatureAlgorithm)

export const isSymmetricSignatureAlgorithm = (alg: string): boolean =>
  symmetricSignatureAlgorithms.includes(alg as (typeof symmetricSignatureAlgorithms)[number])

/**
 * Whether `alg` is a registered signature algorithm in a different casing, such as `hs256`. None of
 * the checks here recognize it, but a case-insensitive comparison downstream could verify it as the
 * registered one. Both casings are compared, as they differ outside ASCII: `ſ` upper cases to `S`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1
 */
export const isJwaSignatureAlgorithmCaseVariant = (alg: string): boolean =>
  typeof alg === 'string' &&
  !isJwaSignatureAlgorithm(alg) &&
  Object.values(JwaSignatureAlgorithm).some(
    (registered) => registered.toLowerCase() === alg.toLowerCase() || registered.toUpperCase() === alg.toUpperCase()
  )
