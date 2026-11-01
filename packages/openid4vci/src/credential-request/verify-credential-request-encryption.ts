import {
  decodeJwtHeader,
  Oauth2ErrorCodes,
  Oauth2ServerErrorResponseError,
  zAlgValueNotNone,
  zCompactJwe,
} from '@openid4vc/oauth2'
import z from 'zod'
import type {
  CredentialIssuerMetadata,
  CredentialRequestEncryptionJwk,
} from '../metadata/credential-issuer/z-credential-issuer-metadata'

const zCredentialRequestJweHeader = z
  .object({
    kid: z.string().min(1),
    alg: zAlgValueNotNone.min(1),
    enc: z.string(),
    zip: z.string().optional(),
    crit: z.array(z.string()).optional(),
  })
  .loose()

type CredentialRequestJweHeader = z.infer<typeof zCredentialRequestJweHeader>

const invalidEncryptionParameters = (error_description: string) =>
  new Oauth2ServerErrorResponseError({
    error: Oauth2ErrorCodes.InvalidEncryptionParameters,
    error_description,
  })

/**
 * Validates an encrypted Credential Request against the issuer's
 * `credential_request_encryption` metadata (OpenID4VCI 1.0 §10 and §12.2.4).
 *
 * @throws Oauth2ServerErrorResponseError with `invalid_encryption_parameters` when the JWE is
 * malformed, uses an unadvertised key or algorithm, or includes unsupported encryption parameters.
 */
export function verifyCredentialRequestEncryption(
  jwe: string,
  credentialIssuerMetadata: Pick<CredentialIssuerMetadata, 'credential_request_encryption'>
): {
  jwk: CredentialRequestEncryptionJwk
  header: CredentialRequestJweHeader
} {
  const supported = credentialIssuerMetadata.credential_request_encryption

  if (!supported) {
    throw invalidEncryptionParameters('Credential request encryption is not supported')
  }

  if (!zCompactJwe.safeParse(jwe).success) {
    throw invalidEncryptionParameters('Credential request is not a compact JWE')
  }

  let header: CredentialRequestJweHeader
  try {
    header = decodeJwtHeader({
      jwt: jwe,
      headerSchema: zCredentialRequestJweHeader,
    }).header
  } catch (error) {
    throw invalidEncryptionParameters(
      `Unable to decode credential request JWE header: ${error instanceof Error ? error.message : 'invalid header'}`
    )
  }

  const jwk = supported.jwks.keys.find((key) => key.kid === header.kid)
  if (!jwk) {
    throw invalidEncryptionParameters('Credential request is not encrypted to a key advertised by the issuer')
  }

  if (header.alg !== jwk.alg) {
    throw invalidEncryptionParameters(
      `Credential request JWE 'alg' must match the advertised key algorithm '${jwk.alg}'`
    )
  }

  if (!supported.enc_values_supported.includes(header.enc)) {
    throw invalidEncryptionParameters(
      `Credential request JWE 'enc' must be one of ${supported.enc_values_supported.map((value) => `'${value}'`).join(', ')}`
    )
  }

  if (header.zip !== undefined) {
    throw invalidEncryptionParameters('Compressed credential requests are not supported')
  }

  if (header.crit !== undefined) {
    throw invalidEncryptionParameters("Credential request JWE must not contain a critical ('crit') header parameter")
  }

  return { jwk, header }
}
