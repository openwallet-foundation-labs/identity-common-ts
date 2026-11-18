import { base64url } from '@owf/identity-common'
import { expect } from 'vitest'
import type { SignJwsCallback, VerifyJwsCallback } from '../callbacks'
import { JoseValidationError, type JoseValidationIssue } from '../error'
import type { Jwk } from '../jwk/z-jwk'

/**
 * An ES256 key with sign and verify callbacks, built on the WebCrypto API.
 *
 * Only for tests: the packages themselves never reach for a global crypto implementation.
 */
export async function createEs256Context(): Promise<{
  publicJwk: Jwk
  signJws: SignJwsCallback
  verifyJws: VerifyJwsCallback
}> {
  const keyPair = await globalThis.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])

  const exported = (await globalThis.crypto.subtle.exportKey('jwk', keyPair.publicKey)) as Jwk
  // `ext` and `key_ops` are added by WebCrypto and say nothing about the key itself
  const { ext: _ext, key_ops: _keyOps, ...publicJwk } = exported

  const signJws: SignJwsCallback = async (_signer, { signingInputBytes }) => {
    const signature = await globalThis.crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      keyPair.privateKey,
      signingInputBytes as Uint8Array<ArrayBuffer>
    )

    return { signature: base64url.encode(new Uint8Array(signature)), signerJwk: publicJwk }
  }

  const verifyJws: VerifyJwsCallback = async (_signer, { signingInputBytes, signature }) => {
    const verified = await globalThis.crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      keyPair.publicKey,
      base64url.decode(signature) as Uint8Array<ArrayBuffer>,
      signingInputBytes as Uint8Array<ArrayBuffer>
    )

    return verified ? { verified: true, signerJwk: publicJwk } : { verified: false }
  }

  return { publicJwk, signJws, verifyJws }
}

/** Builds a compact JWS from a header and payload, without a valid signature. */
export function unsignedCompactJws(header: unknown, payload: unknown, signature = 'c2lnbmF0dXJl'): string {
  const encode = (value: unknown) => base64url.encode(new TextEncoder().encode(JSON.stringify(value)))
  return `${encode(header)}.${encode(payload)}.${signature}`
}

/** Matches a `JoseValidationError` with an issue of `code` at `path`. */
export const validationIssue = (path: Array<string | number>, code: JoseValidationIssue['code']) =>
  expect.objectContaining({
    name: JoseValidationError.name,
    issues: expect.arrayContaining([expect.objectContaining({ code, path })]),
  })

/** Matches a `JoseValidationError` with an issue of `code` at `claim`, with `message` when given. */
export const claimIssue = (claim: string, code: JoseValidationIssue['code'], message?: string) =>
  expect.objectContaining({
    name: JoseValidationError.name,
    issues: expect.arrayContaining([expect.objectContaining({ code, path: [claim], ...(message && { message }) })]),
  })
