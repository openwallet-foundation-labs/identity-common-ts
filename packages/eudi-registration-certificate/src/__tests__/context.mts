import { p256 } from '@noble/curves/nist.js'
import { CoseKey, RegisteredCwtHeaderClaimKey, type Sign1Context, SignatureAlgorithm } from '@owf/cose'
import { ES256, pemToDer } from '@owf/crypto'
import { base64, base64url, base64urlEncode, secondsToDate } from '@owf/identity-common'
import type { Jwk, SignJwsCallback } from '@owf/jose'
import { StatusList, StatusListCwt } from '@owf/token-status-list'
import { registrationCertificate, type VerifyRegistrationCertificateCallbacks, WRP_ENTITLEMENTS } from '../index'

export const sign1Context: Sign1Context = {
  sign: async ({ key, toBeSigned }) => p256.sign(toBeSigned, key.privateKey, { format: 'compact' }),
  verify: async ({ key, signature, toBeVerified }) =>
    p256.verify(signature, toBeVerified, key.publicKey, { lowS: false }),
}

export const signingKey = CoseKey.fromJwk({
  kty: 'EC',
  crv: 'P-256',
  alg: 'ES256',
  x: 'usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8',
  y: 'IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4',
  d: 'V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM',
})

export const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIIBczCCARmgAwIBAgIUZt2jkmAgIIiw/wpvJU/4yL7ek/YwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yNjAzMTYxODEwMTJaFw0zNjAzMTMxODEwMTJa
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASa6ViW
voU/uOZiBHqFWLE/s+3Ts2K6XT9x2S+abUz/xu48DnP8eL89DQRS8TIUewZbW+H6
GBuyFJjG/mSuqJf+o1MwUTAdBgNVHQ4EFgQUFDKBWF8aGWeDTQHphAhWXs9/J1Aw
HwYDVR0jBBgwFoAUFDKBWF8aGWeDTQHphAhWXs9/J1AwDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNIADBFAiEAibvAwfagitnTA7zKxcl8kuUaU+oBLClK8YXg
s2WfHbwCIAQKqu6+GHkzWH8H0zMPKedvxJp34whrGoIarukWZjjp
-----END CERTIFICATE-----`

export const SUB = 'LEINL-529900T8BM49AURSDO55'

export const STATUS_LIST_URI = 'https://registry.test/statuslists/1'

export const payload = registrationCertificate()
  .name('Example')
  .legalName('Example N.V.')
  .identifier(SUB)
  .country('NL')
  .registryUri('https://registry.test/wrp')
  .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
  .supervisoryAuthority({ email: 'dpa@example.nl' })
  .certificateId('wrprc-1')
  .issuedAt(1_700_000_000)
  .expiresAt(1_710_000_000)
  .status({ status_list: { idx: 3, uri: STATUS_LIST_URI } })
  .build()

// The key JWTs are signed with in the tests
const jwsKeys = await ES256.generateKeyPair()
const jwsVerifier = await ES256.getVerifier(jwsKeys.publicKey)
const jwsSigner = await ES256.getSigner(jwsKeys.privateKey)

/** Sign with the test key, whichever certificate the token names */
export const signJwsCallback: SignJwsCallback = async (_, { signingInput }) => ({
  signature: await jwsSigner(signingInput),
  signerJwk: jwsKeys.publicKey as Jwk,
})

/** Trust the test keys, whichever certificate the token names */
export const callbacks: VerifyRegistrationCertificateCallbacks = {
  verifyJws: async (_, { signingInput, signature }) =>
    (await jwsVerifier(signingInput, signature))
      ? { verified: true, signerJwk: jwsKeys.publicKey as Jwk }
      : { verified: false },
  verifyCose: ({ toBeVerified, signature }) =>
    p256.verify(signature, toBeVerified, signingKey.publicKey, { lowS: false }),
}

/** A status list where index 1 is revoked and the others are valid (REV-6.2.6.2-04) */
const statusList = () => new StatusList([0, 1, 0, 0], 1)

export const statusListJwt = async ({
  iat,
  sub = STATUS_LIST_URI,
  typ = 'statuslist+jwt',
}: {
  iat: number
  sub?: string
  typ?: string
}) => {
  const payload = {
    sub,
    iat,
    status_list: { bits: 1, lst: base64url.encode(statusList().compressStatusListToBytes()) },
  }
  const signingInput = `${base64urlEncode(JSON.stringify({ alg: 'ES256', typ }))}.${base64urlEncode(JSON.stringify(payload))}`
  return `${signingInput}.${await jwsSigner(signingInput)}`
}

export const statusListCwt = ({ iat }: { iat: number }) =>
  new StatusListCwt({
    protectedHeaders: new Map<number, unknown>([
      [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
      [RegisteredCwtHeaderClaimKey.X5Chain, base64.decode(pemToDer(TEST_CERT))],
    ]),
    payload: { subject: STATUS_LIST_URI, statusList: statusList(), issuedAt: secondsToDate(iat) },
  }).signAndEncode({ signingKey }, sign1Context)

export const servedAs =
  (body: string | Uint8Array, contentType: string): typeof fetch =>
  async () =>
    new Response(body as BodyInit, { headers: { 'Content-Type': contentType } })
