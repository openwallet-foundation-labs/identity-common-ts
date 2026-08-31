import { describe, expect, test } from 'vitest'
import {
  CoseInvalidSignatureError,
  CoseKey,
  Cwt,
  CwtClaimVerificationError,
  CwtMissingVerifyContextError,
  CwtNotSignedError,
  CwtPayload,
  MacAlgorithm,
  RegisteredCwtClaimKey,
  SignatureAlgorithm,
} from '../cose'
import { mac0Context, macKey, sign1Context, signKey } from './context'

// A second key pair, to check that a token does not verify against a key that did not sign it.
const otherSignKey = CoseKey.fromJwk({
  kty: 'EC',
  crv: 'P-256',
  alg: 'ES256',
  x: 'R7D-W2d9MEVRN_5P23yN9SodkjMEHI2Np_YHD02eTCQ',
  y: 'c5Ynunf6XyarMKXt0hWEezNzsZv01uQpCnpT-qJoll8',
})

const now = new Date('2026-01-01T12:00:00.000Z')
const minutes = (count: number) => new Date(now.getTime() + count * 60_000)

enum ExampleClaimKey {
  Nickname = 65000,
}

const payload = (options: Parameters<typeof CwtPayload.create>[0] = {}) =>
  CwtPayload.create({
    issuer: 'https://issuer.example',
    subject: 'https://subject.example',
    audience: ['https://verifier.example'],
    issuedAt: minutes(-5),
    notBefore: minutes(-5),
    expirationTime: minutes(5),
    additionalClaims: new Map([[ExampleClaimKey.Nickname, 'lamp']]),
    ...options,
  })

describe('CwtPayload.verifyClaims', () => {
  test('accepts a token whose claims are in order', () => {
    expect(() =>
      payload().verifyClaims({
        now,
        expectedIssuer: 'https://issuer.example',
        expectedSubject: 'https://subject.example',
        expectedAudience: ['https://other.example', 'https://verifier.example'],
        requiredClaims: [RegisteredCwtClaimKey.Issuer, RegisteredCwtClaimKey.IssuedAt],
      })
    ).not.toThrow()
  })

  test('requires nothing by default, since the cwt type decides what a token must carry', () => {
    expect(() => CwtPayload.create().verifyClaims()).not.toThrow()
    expect(() => CwtPayload.create().verifyClaims({ now, expectedIssuer: 'https://issuer.example' })).not.toThrow()
  })

  test('rejects a required claim that is absent, naming it', () => {
    const options = { now, requiredClaims: [RegisteredCwtClaimKey.ExpirationTime] }

    expect(() => CwtPayload.create().verifyClaims(options)).toThrow(CwtClaimVerificationError)
    expect(() => CwtPayload.create().verifyClaims(options)).toThrow(
      "The token has no 'ExpirationTime (4)' claim, which is required"
    )
  })

  test('can require a claim the cwt type adds, and names it from keyLabels', () => {
    const options = { now, requiredClaims: [ExampleClaimKey.Nickname], keyLabels: ExampleClaimKey }

    expect(() => payload().verifyClaims(options)).not.toThrow()
    expect(() => CwtPayload.create().verifyClaims(options)).toThrow(
      "The token has no 'Nickname (65000)' claim, which is required"
    )
  })

  test.each([
    ['iss', { expectedIssuer: 'https://other.example' }, "'Issuer (1)'"],
    ['sub', { expectedSubject: 'https://other.example' }, "'Subject (2)'"],
    ['aud', { expectedAudience: 'https://other.example' }, "'Audience (3)'"],
  ])('rejects a %s that is not the expected one', (_, options, label) => {
    expect(() => payload().verifyClaims({ now, ...options })).toThrow('does not match the expected value')
    expect(() => payload().verifyClaims({ now, ...options })).toThrow(label)
  })

  test('accepts an audience that contains one of the expected values', () => {
    expect(() =>
      payload({ audience: ['https://other.example', 'https://verifier.example'] }).verifyClaims({
        now,
        expectedAudience: 'https://verifier.example',
      })
    ).not.toThrow()
  })

  test('applies the clock skew to the expiration', () => {
    const expirationTime = minutes(-0.25)
    const expired = payload({ expirationTime })

    expect(() => expired.verifyClaims({ now })).not.toThrow()
    expect(() => expired.verifyClaims({ now, skewSeconds: 1 })).toThrow(
      `The 'ExpirationTime (4)' claim '${expirationTime.toISOString()}' is in the past (compared to '${now.toISOString()}'), and therefore not valid`
    )
    expect(() => expired.verifyClaims({ now, skewSeconds: 1, checkExpirationTime: false })).not.toThrow()
  })

  test.each([
    ['nbf', 'notBefore', "'NotBefore (5)'", 'checkNotBefore'],
    ['iat', 'issuedAt', "'IssuedAt (6)'", 'checkIssuedAt'],
  ] as const)('applies the clock skew to %s', (_, claim, label, check) => {
    const notYetValid = payload({ [claim]: minutes(0.25) })

    expect(() => notYetValid.verifyClaims({ now })).not.toThrow()
    expect(() => notYetValid.verifyClaims({ now, skewSeconds: 1 })).toThrow('is in the future')
    expect(() => notYetValid.verifyClaims({ now, skewSeconds: 1 })).toThrow(label)
    expect(() => notYetValid.verifyClaims({ now, skewSeconds: 1, [check]: false })).not.toThrow()
  })
})

describe('Cwt.verify', () => {
  const signedToken = async () =>
    await Cwt.create({ payload: payload() }).signAndEncode(
      { signingKey: signKey, algorithm: SignatureAlgorithm.ES256 },
      sign1Context
    )

  const macedToken = async () => {
    const cwt = Cwt.create({ payload: payload() })
    cwt.protectedHeaders.headers.set(1, MacAlgorithm.HS256)
    return await cwt.authenticateAndEncode({ key: macKey }, mac0Context)
  }

  test('verifies the signature and the claims of a signed cwt', async () => {
    const cwt = Cwt.fromToken(await signedToken(), { payload: CwtPayload })

    expect(cwt.signature).toBeDefined()
    expect(cwt.tag).toBeUndefined()
    await expect(
      cwt.verify({ key: signKey, now, expectedSubject: 'https://subject.example' }, { sign1: sign1Context })
    ).resolves.toBeUndefined()
  })

  test('verifies the authentication tag and the claims of a maced cwt', async () => {
    const cwt = Cwt.fromToken(await macedToken(), { payload: CwtPayload })

    expect(cwt.tag).toBeDefined()
    expect(cwt.signature).toBeUndefined()
    await expect(cwt.verify({ key: macKey, now }, { mac0: mac0Context })).resolves.toBeUndefined()
  })

  test('rejects a token it has no verification context for', async () => {
    const signed = Cwt.fromToken(await signedToken(), { payload: CwtPayload })
    const maced = Cwt.fromToken(await macedToken(), { payload: CwtPayload })

    // The context carries both, so a caller does not have to know which structure a token turned
    // out to be; one that only carries the other is a mismatch the CWT reports rather than uses.
    await expect(signed.verify({ key: signKey, now }, { mac0: mac0Context })).rejects.toThrow(
      CwtMissingVerifyContextError
    )
    await expect(maced.verify({ key: macKey, now }, { sign1: sign1Context })).rejects.toThrow(
      CwtMissingVerifyContextError
    )
    await expect(
      signed.verify({ key: signKey, now }, { sign1: sign1Context, mac0: mac0Context })
    ).resolves.toBeUndefined()
    await expect(
      maced.verify({ key: macKey, now }, { sign1: sign1Context, mac0: mac0Context })
    ).resolves.toBeUndefined()
  })

  test('rejects a token that does not verify with the given key', async () => {
    const cwt = Cwt.fromToken(await signedToken(), { payload: CwtPayload })

    await expect(cwt.verify({ key: otherSignKey, now }, { sign1: sign1Context })).rejects.toThrow(
      CoseInvalidSignatureError
    )
  })

  test('rejects the claims only once the signature is established', async () => {
    const cwt = Cwt.fromToken(await signedToken(), { payload: CwtPayload })

    // A token whose signature does not verify is rejected for that, not for its claims
    await expect(cwt.verify({ key: otherSignKey, now: minutes(60) }, { sign1: sign1Context })).rejects.toThrow(
      CoseInvalidSignatureError
    )
    await expect(cwt.verify({ key: signKey, now: minutes(60) }, { sign1: sign1Context })).rejects.toThrow(
      CwtClaimVerificationError
    )
  })
})

describe('Cwt with an external aad', () => {
  const externalAad = new Uint8Array([1, 2, 3])

  test('round-trips the aad through signing and verification', async () => {
    const token = await Cwt.create({ payload: payload() }).signAndEncode(
      { signingKey: signKey, algorithm: SignatureAlgorithm.ES256, externalAad },
      sign1Context
    )
    const cwt = Cwt.fromToken(token, { payload: CwtPayload })

    // Regression: the aad used to live on the structure, and `signAndEncode` did not pass it into
    // signing, so a CWT signed with an aad did not verify against that same aad.
    await expect(cwt.verify({ key: signKey, now, externalAad }, { sign1: sign1Context })).resolves.toBeUndefined()
    await expect(cwt.verify({ key: signKey, now }, { sign1: sign1Context })).rejects.toThrow(CoseInvalidSignatureError)
  })

  test('round-trips the aad for a maced cwt', async () => {
    const cwt = Cwt.create({ payload: payload() })
    cwt.protectedHeaders.headers.set(1, MacAlgorithm.HS256)
    const token = await cwt.authenticateAndEncode({ key: macKey, externalAad }, mac0Context)
    const decoded = Cwt.fromToken(token, { payload: CwtPayload })

    await expect(decoded.verify({ key: macKey, now, externalAad }, { mac0: mac0Context })).resolves.toBeUndefined()
    await expect(decoded.verify({ key: macKey, now }, { mac0: mac0Context })).rejects.toThrow(CoseInvalidSignatureError)
  })
})

describe('Cwt.verify without a signature or tag', () => {
  test('reports that there is nothing to verify', async () => {
    const cwt = Cwt.create({ payload: payload() })

    expect(cwt.signature).toBeUndefined()
    expect(cwt.tag).toBeUndefined()
    await expect(cwt.verify({ key: signKey, now }, { sign1: sign1Context })).rejects.toThrow(CwtNotSignedError)
  })

  test('rejects a cwt built with both a signature and a tag', () => {
    expect(() => new Cwt({ payload: payload(), signature: new Uint8Array([1]), tag: new Uint8Array([2]) })).toThrow(
      'not both'
    )
  })
})
