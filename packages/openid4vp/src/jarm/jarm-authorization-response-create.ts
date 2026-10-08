import { type CallbackContext, Oauth2Error } from '@openid4vc/oauth2'
import { type JweEncryptor, type JwsSigner, jwsHeaderFromSigner, signJwt } from '@owf/jose'
import type {
  JarmAuthorizationResponse,
  JarmAuthorizationResponseEncryptedOnly,
} from './jarm-authorization-response/z-jarm-authorization-response'

export interface CreateJarmAuthorizationResponseOptions {
  jarmAuthorizationResponse: JarmAuthorizationResponse | JarmAuthorizationResponseEncryptedOnly
  jwtSigner?: JwsSigner
  jweEncryptor?: JweEncryptor
  callbacks: Pick<CallbackContext, 'signJws' | 'encryptJwe'>
}

export async function createJarmAuthorizationResponse(options: CreateJarmAuthorizationResponseOptions) {
  const { jarmAuthorizationResponse, jweEncryptor, jwtSigner, callbacks } = options
  if (!jwtSigner && jweEncryptor) {
    const { jwe } = await callbacks.encryptJwe(jweEncryptor, JSON.stringify(jarmAuthorizationResponse))
    return { jarmAuthorizationResponseJwt: jwe }
  }

  if (jwtSigner && !jweEncryptor) {
    const signed = await signJwt({
      header: jwsHeaderFromSigner(jwtSigner),
      payload: jarmAuthorizationResponse,
      signer: jwtSigner,
      signJwsCallback: callbacks.signJws,
    })
    return { jarmAuthorizationResponseJwt: signed.jwt }
  }

  if (!jwtSigner || !jweEncryptor) {
    throw new Oauth2Error('JWT signer and/or encryptor are required to create a JARM auth response.')
  }
  const signed = await signJwt({
    header: jwsHeaderFromSigner(jwtSigner),
    payload: jarmAuthorizationResponse,
    signer: jwtSigner,
    signJwsCallback: callbacks.signJws,
  })

  const encrypted = await callbacks.encryptJwe(jweEncryptor, signed.jwt)

  return { jarmAuthorizationResponseJwt: encrypted.jwe }
}
