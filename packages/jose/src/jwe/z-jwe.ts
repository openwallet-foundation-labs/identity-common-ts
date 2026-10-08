import type { OrPromise } from '@owf/identity-common'
import z from 'zod'
import { zJweAlg, zJweEnc } from '../jwa/z-alg'
import type { Jwk } from '../jwk/z-jwk'
import { zPublicJwk } from '../jwk/z-jwk'
import { zX5c } from '../jwk/z-x5c'
import type { JwsSignerJwk } from '../jws/signer'

/**
 * A JWE in compact serialization.
 *
 * The encrypted key part may be empty, as it is for direct key agreement (`ECDH-ES`) and direct
 * encryption (`dir`).
 *
 * @see https://www.rfc-editor.org/rfc/rfc7516#section-7.1
 */
export const zCompactJwe = z
  .string()
  .regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/, {
    message: 'Not a valid compact JWE',
  })

/**
 * The header parameters registered for a JWE.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7516#section-4.1
 */
export const zJweHeader = z
  .object({
    alg: zJweAlg,
    enc: zJweEnc,

    typ: z.string().optional(),
    cty: z.string().optional(),
    zip: z.string().optional(),

    kid: z.string().optional(),
    jwk: zPublicJwk.optional(),
    jku: z.string().optional(),

    x5c: zX5c.optional(),
    x5u: z.string().optional(),
    x5t: z.string().optional(),
    'x5t#S256': z.string().optional(),

    crit: z.array(z.string().min(1)).min(1).optional(),

    /** The ephemeral public key of the originator, for the key agreement algorithms. */
    epk: zPublicJwk.optional(),

    /** Agreement PartyUInfo, base64url encoded. */
    apu: z.string().optional(),

    /** Agreement PartyVInfo, base64url encoded. */
    apv: z.string().optional(),
  })
  .loose()

export type JweHeader = z.infer<typeof zJweHeader>

/**
 * The recipient a JWE is encrypted for, and how.
 *
 * Encryption and decryption themselves are performed by callbacks: this package models the
 * structures and leaves the cryptography to the caller.
 */
export type JweEncryptor = JwsSignerJwk & {
  /** The content encryption algorithm. */
  enc: string

  /** Agreement PartyUInfo, base64url encoded. */
  apu?: string

  /** Agreement PartyVInfo, base64url encoded. */
  apv?: string
}

/** Encrypts `data` for `encryptor`, returning the JWE in compact serialization. */
export type EncryptJweCallback = (
  encryptor: JweEncryptor,
  data: string
) => OrPromise<{
  encryptionJwk: Jwk
  jwe: string
}>

export interface DecryptJweCallbackOptions {
  /** The key to decrypt with, when the caller knows which one applies. */
  jwk?: Jwk
}

/**
 * Decrypts a compact JWE, returning the plaintext and the JWK of the key it was decrypted with.
 *
 * Return `{ decrypted: false }` for expected failures, such as an invalid ciphertext or
 * authentication tag or a key mismatch. Throw only for unexpected failures, such as an unavailable
 * key store.
 */
export type DecryptJweCallback = (
  jwe: string,
  options?: DecryptJweCallbackOptions
) => OrPromise<
  | {
      decrypted: true
      decryptionJwk: Jwk
      payload: string
    }
  | {
      decrypted: false
      decryptionJwk?: Jwk
      payload?: string
    }
>
