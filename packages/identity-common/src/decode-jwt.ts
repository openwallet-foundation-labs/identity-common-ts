import { base64urlDecodeJson } from './base64url'
import { IdentityCommonException } from './identity-common-exception'

/**
 * Decode a JWT in compact JWS serialization without verifying the signature.
 *
 * The header and payload are decoded with {@link base64urlDecodeJson}, so invalid base64url,
 * invalid UTF-8 and invalid JSON are all rejected with the same error.
 */
export const decodeJwt = <H extends Record<string, unknown>, T extends Record<string, unknown>>(
  jwt: string
): { header: H; payload: T; signature: string } => {
  const { 0: header, 1: payload, 2: signature, length } = jwt.split('.')
  if (length !== 3) {
    throw new IdentityCommonException('Invalid JWT as input')
  }

  try {
    return {
      header: base64urlDecodeJson<H>(header),
      payload: base64urlDecodeJson<T>(payload),
      signature: signature,
    }
  } catch {
    throw new IdentityCommonException('Invalid JWT as input')
  }
}
