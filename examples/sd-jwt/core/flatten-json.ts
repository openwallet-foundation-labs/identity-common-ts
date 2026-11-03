import type { DisclosureFrame } from '@sd-jwt/core'
import { FlattenJson, SdJwtInstance } from '@sd-jwt/core'
import { createSignerVerifier, digest, ES256, generateSalt } from './utils'

;(async () => {
  const { signer, verifier } = await createSignerVerifier()

  // Create SdJwt instance for use
  const sdjwt = new SdJwtInstance({
    signer,
    signAlg: ES256.alg,
    verifier,
    hasher: digest,
    saltGenerator: generateSalt,
    kbSigner: signer,
    kbSignAlg: ES256.alg,
    kbVerifier: verifier,
  })
  const claims = {
    firstname: 'John',
    lastname: 'Doe',
    ssn: '123-45-6789',
    id: '1234',
  }
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['firstname', 'id'],
  }

  const KbJwtPayload = {
    iat: Math.floor(Date.now() / 1000),
    aud: 'https://example.com',
    nonce: '1234',
    custom: 'data',
  }

  const encodedSdjwt = await sdjwt.issue(claims, disclosureFrame)
  console.log('encodedSdjwt:', encodedSdjwt)

  const flattenJson = FlattenJson.fromEncode(encodedSdjwt)
  console.log('flattenJson(credential): ', flattenJson.toJson())

  const presentedSdJwt = await sdjwt.present<typeof claims>(
    encodedSdjwt,
    { id: true },
    {
      kb: {
        payload: KbJwtPayload,
      },
    }
  )

  const flattenPresentationJson = FlattenJson.fromEncode(presentedSdJwt)
  console.log('flattenJson(presentation): ', flattenPresentationJson.toJson())

  const verified = await sdjwt.verify(presentedSdJwt, {
    requiredClaimKeys: ['id'],
    keyBindingNonce: '1234',
  })
  console.log(verified)
})()
