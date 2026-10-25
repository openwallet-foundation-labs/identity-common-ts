import { base64url, base64urlDecodeJson, stringToBytes } from '@owf/identity-common'

type JsonWebTokenParts = {
  header: Record<string, unknown>
  claims: Record<string, unknown>
  signature: Uint8Array
  signableInput: Uint8Array
}

export const parseJsonWebToken = (jwt: string): JsonWebTokenParts => {
  const [encodedHeader, encodedClaims, encodedSignature] = jwt.split('.')

  if (!encodedHeader) {
    throw new Error('could not find the header in the JWT')
  }

  if (!encodedClaims) {
    throw new Error('could not find the claims in the JWT')
  }

  if (!encodedSignature) {
    throw new Error('could not find the signature in the JWT')
  }

  const header = base64urlDecodeJson<Record<string, unknown>>(encodedHeader)
  const claims = base64urlDecodeJson<Record<string, unknown>>(encodedClaims)
  const signature = base64url.decode(encodedSignature)

  return {
    header,
    claims,
    signature,
    signableInput: stringToBytes(`${encodedHeader}.${encodedClaims}`),
  }
}
