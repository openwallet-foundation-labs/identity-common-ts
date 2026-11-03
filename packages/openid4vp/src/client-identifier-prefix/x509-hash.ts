import type { CallbackContext } from '@openid4vc/oauth2'
import { base64, base64url } from '@owf/identity-common'

export async function calculateX509HashClientIdPrefixValue({
  x509Certificate,
  hash,
}: {
  /**
   * DER encoded x509 certificate. Either encoded as base64 or directly as Uint8Array
   */
  x509Certificate: string | Uint8Array

  hash: CallbackContext['hash']
}) {
  return base64url.encode(
    await hash(
      new Uint8Array(typeof x509Certificate === 'string' ? base64.decode(x509Certificate) : x509Certificate).buffer,
      'sha-256'
    )
  )
}
