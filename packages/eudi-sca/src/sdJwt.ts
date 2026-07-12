import { base64url, type Hasher } from '@owf/identity-common'
import type { KBJwt } from '@sd-jwt/core'
import type { Signer } from '@sd-jwt/types'
import { type CreateResponseClaimsOptions, createResponseClaims } from './responseClaims'

export type CreateKbJwtOptions = CreateResponseClaimsOptions & {
  kbJwt: KBJwt
}

export const createKbJwt = async (
  options: CreateKbJwtOptions,
  ctx: { hasher: Hasher; getRandomValues: (length: number) => Uint8Array; signer?: Signer }
) => {
  const responseClaims = await createResponseClaims(options, ctx)

  if (!options.kbJwt.payload) {
    throw new Error('Payload is not defined on the provided kbjwt')
  }

  const responseClaimKeys = new Set(Object.keys(responseClaims))
  const payloadKeys = new Set(Object.keys(options.kbJwt.payload))

  const duplicateKeys = [...responseClaimKeys].filter((key) => payloadKeys.has(key))
  if (duplicateKeys.length > 0) {
    throw new Error(
      `Duplicate claims found in both responseClaims and in the payload of the kbJwt: [${duplicateKeys.join(', ')}]`
    )
  }

  const kbJwtClaims = {
    ...responseClaims,
    ...options.kbJwt.payload,
    transaction_data_hash: base64url.encode(responseClaims.transaction_data_hash),
  }

  // type casting is required here as `setPayload` is defined on `Jwt` which explicitly returns `Jwt` with `setPayload`
  const combinedKbJwt = options.kbJwt.setPayload(kbJwtClaims) as unknown as KBJwt

  if (ctx.signer) {
    return await combinedKbJwt.sign(ctx.signer)
  }

  return combinedKbJwt
}
