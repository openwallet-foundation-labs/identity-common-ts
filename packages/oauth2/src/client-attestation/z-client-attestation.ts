import { zHttpsUrl } from '@openid4vc/utils'
import { zNonEmptyString, zNumericDate, zTyp } from '@owf/identity-common'
import { zJwk, zJwtHeader, zJwtPayload } from '@owf/jose'
import z from 'zod'

export const zOauthClientAttestationHeader = z.literal('OAuth-Client-Attestation')
export const oauthClientAttestationHeader = zOauthClientAttestationHeader.value

export const zClientAttestationJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    sub: zNonEmptyString,
    exp: zNumericDate,
    cnf: z
      .object({
        jwk: zJwk,
      })
      .loose(),

    // OID4VCI Wallet Attestation Extensions
    wallet_name: z.string().optional(),
    wallet_link: z.url().optional(),
  })
  .loose()
export type ClientAttestationJwtPayload = z.infer<typeof zClientAttestationJwtPayload>

export const zClientAttestationJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: zTyp('oauth-client-attestation+jwt'),
  })
  .loose()

export type ClientAttestationJwtHeader = z.infer<typeof zClientAttestationJwtHeader>

export const zOauthClientAttestationPopHeader = z.literal('OAuth-Client-Attestation-PoP')
export const oauthClientAttestationPopHeader = zOauthClientAttestationPopHeader.value

// draft 09: header used by the authorization/resource server to provide a fresh challenge.
export const zOauthClientAttestationChallengeHeader = z.literal('OAuth-Client-Attestation-Challenge')
export const oauthClientAttestationChallengeHeader = zOauthClientAttestationChallengeHeader.value

// draft 09 §6.1: response body of the authorization server's `challenge_endpoint`.
export const zClientAttestationChallengeResponse = z.object({ attestation_challenge: zNonEmptyString }).loose()
export type ClientAttestationChallengeResponse = z.infer<typeof zClientAttestationChallengeResponse>

export const zClientAttestationPopJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    aud: z.union([zHttpsUrl, z.array(zHttpsUrl)]),

    // REQUIRED (draft 09 §5.2), as the freshness of the PoP is checked against it
    iat: zNumericDate,
    jti: zNonEmptyString,

    // `challenge` (draft 06+) replaced `nonce`. Both are accepted on verification; `nonce`
    // is retained only for backwards compatibility with <= draft 05 PoP JWTs.
    challenge: z.optional(zNonEmptyString),
    nonce: z.optional(zNonEmptyString),
  })
  .loose()
export type ClientAttestationPopJwtPayload = z.infer<typeof zClientAttestationPopJwtPayload>

export const zClientAttestationPopJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: zTyp('oauth-client-attestation-pop+jwt'),
  })
  .loose()
export type ClientAttestationPopJwtHeader = z.infer<typeof zClientAttestationPopJwtHeader>
