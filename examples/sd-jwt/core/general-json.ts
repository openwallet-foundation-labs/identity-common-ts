import type { DisclosureFrame } from '@sd-jwt/core'
import { GeneralJson, SdJwtGeneralJsonInstance, SdJwtInstance } from '@sd-jwt/core'
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
  const generalJsonSdJwt = new SdJwtGeneralJsonInstance({
    hasher: digest,
    verifier,
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

  const generalJson = GeneralJson.fromEncode(encodedSdjwt)
  console.log('generalJson(credential): ', generalJson.toJson())

  const presentedSdJwt = await sdjwt.present<typeof claims>(
    encodedSdjwt,
    { id: true },
    {
      kb: {
        payload: KbJwtPayload,
      },
    }
  )

  const generalPresentationJson = GeneralJson.fromEncode(presentedSdJwt)

  await generalPresentationJson.addSignature(
    {
      alg: 'ES256',
      typ: 'sd+jwt',
      kid: 'key-1',
    },
    signer,
    'key-1'
  )

  console.log('flattenJson(presentation): ', JSON.stringify(generalPresentationJson.toJson(), null, 2))

  const verified = await sdjwt.verify(presentedSdJwt, {
    requiredClaimKeys: ['id'],
    keyBindingNonce: '1234',
  })
  console.log(verified)

  const generalVerified = await generalJsonSdJwt.verify(generalJson)
  console.log(generalVerified)
})()
