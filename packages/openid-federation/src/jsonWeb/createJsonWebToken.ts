import { base64url, base64urlEncode } from '@owf/identity-common'

/**
 *
 * Create a json web token according to {@link https://datatracker.ietf.org/doc/html/rfc7519 | RFC7519 }
 *
 */
export const createJsonWebToken = (
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signature: Uint8Array
) => {
  const encodedHeader = base64urlEncode(JSON.stringify(header))
  const encodedPayload = base64urlEncode(JSON.stringify(payload))

  const encodedSignature = base64url.encode(signature)

  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`
}
