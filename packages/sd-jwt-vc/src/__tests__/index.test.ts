import Crypto from 'node:crypto'
import { hasher as digest, generateSalt } from '@owf/crypto'
import { base64url } from '@owf/identity-common'
import { JoseValidationError, StatusList, StatusListError } from '@owf/token-status-list'
import {
  type DisclosureFrame,
  JwtTimeClaimError,
  SdJwtError,
  SdJwtInstance,
  type Signer,
  type Verifier,
} from '@sd-jwt/core'
import { SignJWT } from 'jose'
import { describe, expect, test, vi } from 'vitest'
import { SdJwtVcInstance } from '..'
import type { SdJwtVcPayload } from '../sd-jwt-vc-payload'

const iss = 'ExampleIssuer'
const vct = 'ExampleCredentialType'
const iat = Math.floor(Date.now() / 1000)

const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519')

//create a separate keypair for the status list
const { privateKey: statusListPrivateKey, publicKey: statusListPublicKey } = Crypto.generateKeyPairSync('ed25519')

//TODO: to simulate a hosted status list, use the same approach as in vct.test.ts

const createSignerVerifier = () => {
  const signer: Signer = async (data: string) => {
    const sig = Crypto.sign(null, Buffer.from(data), privateKey)
    return Buffer.from(sig).toString('base64url')
  }
  const verifier: Verifier = async (data: string, sig: string) => {
    return Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'))
  }
  return { signer, verifier }
}

// A plain SD-JWT issuer does not apply the SD-JWT VC rules, so it can make a protected claim disclosable
class PlainSdJwtVcIssuer extends SdJwtInstance<SdJwtVcPayload> {
  protected type = 'dc+sd-jwt'
}

const signStatusList = (
  key: Crypto.KeyObject,
  statusList: StatusList,
  claims: Record<string, unknown>,
  typ = 'statuslist+jwt'
) =>
  new SignJWT({
    ...claims,
    status_list: { bits: statusList.getBitsPerStatus(), lst: base64url.encode(statusList.compressStatusListToBytes()) },
  })
    .setProtectedHeader({ alg: 'EdDSA', typ })
    .sign(key)

const statusListJWT = await signStatusList(statusListPrivateKey, new StatusList([0, 1, 0, 0, 0, 0, 1, 1], 1), {
  iss: 'https://example.com',
  sub: 'https://example.com/status-list',
  iat,
})

describe('App', () => {
  test('Example', async () => {
    const { signer, verifier } = createSignerVerifier()
    const sdjwt = new SdJwtVcInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
    })

    const claims = {
      firstname: 'John',
    }
    const disclosureFrame = {
      _sd: ['firstname', 'iss'],
    }

    const expectedPayload: SdJwtVcPayload = { iat, iss, vct, ...claims }
    const encodedSdjwt = sdjwt.issue(expectedPayload, disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>)
    await expect(encodedSdjwt).rejects.toThrowError()
  })

  test('rejects a disclosure frame that makes vct#integrity selectively disclosable', async () => {
    const { signer, verifier } = createSignerVerifier()
    const sdjwt = new SdJwtVcInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
    })

    const payload: SdJwtVcPayload = { iat, iss, vct, 'vct#integrity': 'sha256-example' }
    const disclosureFrame = { _sd: ['vct#integrity'] } as unknown as DisclosureFrame<SdJwtVcPayload>
    await expect(sdjwt.issue(payload, disclosureFrame)).rejects.toThrowError('Cannot disclose protected field')
  })

  test.each([
    ['iss', iss],
    ['nbf', iat],
    ['exp', iat + 3600],
    ['cnf', { jwk: { kty: 'OKP', crv: 'Ed25519', x: 'x' } }],
    ['vct', vct],
    ['vct#integrity', 'sha256-example'],
    ['aka_vcts', ['urn:example:other-type']],
  ])('rejects a credential in which %s was selectively disclosed', async (claim, value) => {
    const { signer, verifier } = createSignerVerifier()
    const config = {
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256' as const,
      saltGenerator: generateSalt,
    }
    const issuer = new PlainSdJwtVcIssuer(config)
    const sdjwt = new SdJwtVcInstance(config)
    const payload: SdJwtVcPayload = { iat, iss, vct, [claim]: value, nested: { [claim]: value } }

    // The same claim inside a disclosable object is not protected
    const control = await issuer.issue(payload, {
      nested: { _sd: [claim] },
    } as unknown as DisclosureFrame<SdJwtVcPayload>)
    await expect(sdjwt.verify(control)).resolves.toHaveProperty('payload')
    await expect(sdjwt.safeVerify(control)).resolves.toMatchObject({ success: true })

    const credential = await issuer.issue(payload, { _sd: [claim] } as unknown as DisclosureFrame<SdJwtVcPayload>)
    await expect(sdjwt.verify(credential)).rejects.toMatchObject({
      code: 'INVALID_SD_JWT',
      message: `Protected claims must not be selectively disclosed: ${claim}`,
    })
    const result = await sdjwt.safeVerify(credential)
    expect(result.success).toBe(false)
    expect(result.errors?.map((e) => e.code)).toEqual(['INVALID_SD_JWT'])
  })

  test('rejects a credential in which status was selectively disclosed', async () => {
    const { signer, verifier } = createSignerVerifier()
    const statusListFetcher = vi.fn(async () => statusListJWT)
    const config = {
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256' as const,
      saltGenerator: generateSalt,
      statusListFetcher,
    }
    const issuer = new PlainSdJwtVcIssuer(config)
    const sdjwt = new SdJwtVcInstance(config)
    const status = { status_list: { idx: 0, uri: 'https://example.com/status-list' } }
    const payload: SdJwtVcPayload = { iat, iss, vct, status }
    const credential = await issuer.issue(payload, { _sd: ['status'] } as unknown as DisclosureFrame<SdJwtVcPayload>)

    await expect(sdjwt.verify(credential)).rejects.toMatchObject({
      code: 'INVALID_SD_JWT',
      message: 'Protected claims must not be selectively disclosed: status',
    })
    const result = await sdjwt.safeVerify(credential)
    expect(result.success).toBe(false)
    expect(result.errors?.map((e) => e.code)).toEqual(['INVALID_SD_JWT'])
    expect(statusListFetcher).not.toHaveBeenCalled()
  })

  test.each([
    ['status', { status: { _sd: ['status_list'] } }],
    ['cnf', { cnf: { _sd: ['jwk'] } }],
    ['cnf', { cnf: { keys: { _sd: [0] } } }],
    ['aka_vcts', { aka_vcts: { _sd: [0] } }],
  ])('rejects a credential in which a part of %s is selectively disclosable', async (claim, frame) => {
    const { signer, verifier } = createSignerVerifier()
    const statusListFetcher = vi.fn(async () => statusListJWT)
    const config = {
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256' as const,
      saltGenerator: generateSalt,
      statusListFetcher,
    }
    const issuer = new PlainSdJwtVcIssuer(config)
    const sdjwt = new SdJwtVcInstance(config)
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'x' }
    const payload: SdJwtVcPayload = {
      iat,
      iss,
      vct,
      status: { status_list: { idx: 0, uri: 'https://example.com/status-list' } },
      cnf: { jwk, keys: [jwk, jwk] },
      aka_vcts: ['urn:example:other-type'],
    }
    const disclosureFrame = frame as unknown as DisclosureFrame<SdJwtVcPayload>

    await expect(sdjwt.issue(payload, disclosureFrame)).rejects.toThrowError('Cannot disclose protected field')

    // Refused whether the holder reveals the part or withholds it
    const credential = await issuer.issue(payload, disclosureFrame)
    for (const presentation of [credential, await issuer.present(credential, {})]) {
      await expect(sdjwt.verify(presentation)).rejects.toMatchObject({
        code: 'INVALID_SD_JWT',
        message: `Protected claims must not have selectively disclosable parts: ${claim}`,
      })
      const result = await sdjwt.safeVerify(presentation)
      expect(result.success).toBe(false)
      expect(result.errors?.map((e) => e.code)).toContain('INVALID_SD_JWT')
    }

    // Also reported when the signature does not verify, from the issuer-signed claims alone
    const rejecting = new SdJwtVcInstance({ ...config, verifier: async () => false })
    const failed = await rejecting.safeVerify(credential)
    expect(failed.errors?.map((e) => e.message)).toContain(
      `Protected claims must not have selectively disclosable parts: ${claim}`
    )
    // The same claim without selectively disclosable parts is not reported
    const control = await rejecting.safeVerify(await issuer.issue(payload, {}))
    expect(control.success).toBe(false)
    expect(control.errors?.map((e) => e.code)).not.toContain('INVALID_SD_JWT')
  })

  // SD-JWT VC draft 23, Section 2.2.1: the typ of an SD-JWT VC MUST be dc+sd-jwt, which replaced vc+sd-jwt
  test.each([['statuslist+jwt'], ['vc+sd-jwt'], ['JWT'], [undefined]])(
    'rejects a JWT of the issuer with the typ %s, as it is no SD-JWT VC',
    async (typ) => {
      const { signer, verifier } = createSignerVerifier()
      const issuer = new SdJwtVcInstance({ signer, signAlg: 'EdDSA', hasher: digest, saltGenerator: generateSalt })
      const statusListFetcher = vi.fn(async () => statusListJWT)
      const vctFetcher = vi.fn(async () => undefined)
      const sdjwt = new SdJwtVcInstance({
        verifier,
        hasher: digest,
        statusListFetcher,
        loadTypeMetadataFormat: true,
        vctFetcher,
      })
      const credential = await issuer.issue(
        { iat, iss, vct, status: { status_list: { idx: 0, uri: 'https://example.com/status-list' } } },
        undefined,
        { header: { typ } }
      )

      await expect(sdjwt.verify(credential)).rejects.toMatchObject({
        code: 'INVALID_SD_JWT',
        message: `Invalid typ header '${typ}': it must be 'dc+sd-jwt'`,
      })
      const result = await sdjwt.safeVerify(credential)
      expect(result.success ? [] : result.errors.map((e) => e.code)).toEqual(['INVALID_SD_JWT'])
      await expect(sdjwt.getVct(credential)).rejects.toThrowError('Invalid typ header')
      expect(statusListFetcher).not.toHaveBeenCalled()
      expect(vctFetcher).not.toHaveBeenCalled()
    }
  )

  // SD-JWT VC draft 23, Section 2.2.1: the issuer MUST include the typ header
  test('refuses to issue without the typ header', async () => {
    const { signer } = createSignerVerifier()
    const issuer = new SdJwtVcInstance({
      signer,
      signAlg: 'EdDSA',
      hasher: digest,
      saltGenerator: generateSalt,
      omitTyp: true,
    })

    await expect(issuer.issue({ iat, iss, vct })).rejects.toThrowError(
      "An SD-JWT-VC must have the typ header 'dc+sd-jwt', so omitTyp is not allowed"
    )
  })

  // RFC 7515 Section 4.1.9: the typ may carry the application/ prefix, and media types are case-insensitive
  test.each([['application/dc+sd-jwt'], ['DC+SD-JWT']])('accepts the typ %s', async (typ) => {
    const { signer, verifier } = createSignerVerifier()
    const issuer = new SdJwtVcInstance({ signer, signAlg: 'EdDSA', hasher: digest, saltGenerator: generateSalt })
    const sdjwt = new SdJwtVcInstance({ verifier, hasher: digest })
    const credential = await issuer.issue({ iat, iss, vct }, undefined, { header: { typ } })

    await expect(sdjwt.verify(credential)).resolves.toMatchObject({ header: { typ } })
    await expect(sdjwt.safeVerify(credential)).resolves.toMatchObject({ success: true })
  })
})

describe('Revocation', () => {
  const { signer, verifier } = createSignerVerifier()
  const sdjwt = new SdJwtVcInstance({
    signer,
    signAlg: 'EdDSA',
    verifier,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
    statusListFetcher(_uri: string) {
      // we emulate fetching the status list from the uri. Validation of the JWT is not done here in the test but should be done in the implementation.
      return Promise.resolve(statusListJWT)
    },
    // statusValidator(status: number) {
    //   // we are only accepting status 0
    //   if (status === 0) return Promise.resolve();
    //   throw new Error('Status is not valid');
    // },
    statusVerifier: async (data: string, sig: string) => {
      //we could also look into the data to extract the public key from the x5c when provided
      return Crypto.verify(null, Buffer.from(data), statusListPublicKey, Buffer.from(sig, 'base64url'))
    },
  })

  test('Test with a non revoked credential', async () => {
    const claims = {
      firstname: 'John',
      status: {
        status_list: {
          uri: 'https://example.com/status-list',
          idx: 0,
        },
      },
    }
    const expectedPayload: SdJwtVcPayload = { iat, iss, vct, ...claims }
    const encodedSdjwt = await sdjwt.issue(expectedPayload)
    const result = await sdjwt.verify(encodedSdjwt)
    expect(result).toBeDefined()
  })

  test.each([
    ['issuer', { expectedIssuer: iss }],
    ['subject', { expectedSubject: 'alice' }],
    ['audience', { expectedAudience: 'credential-audience' }],
    ['VCT', { expectedVct: vct }],
    [
      'combined options',
      {
        expectedIssuer: iss,
        expectedSubject: 'alice',
        expectedAudience: 'credential-audience',
        expectedVct: vct,
      },
    ],
  ])('applies expected %s only to the credential, not the status list token', async (_name, expected) => {
    const encoded = await sdjwt.issue({
      iat,
      iss,
      sub: 'alice',
      aud: 'credential-audience',
      vct,
      status: { status_list: { uri: 'https://example.com/status-list', idx: 0 } },
    })

    await expect(sdjwt.verify(encoded, expected)).resolves.toBeDefined()
  })

  test('Test with a revoked credential', async () => {
    const claims = {
      firstname: 'John',
      status: {
        status_list: {
          uri: 'https://example.com/status-list',
          idx: 1,
        },
      },
    }
    const expectedPayload: SdJwtVcPayload = { iat, iss, vct, ...claims }
    const encodedSdjwt = await sdjwt.issue(expectedPayload)
    const result = sdjwt.verify(encodedSdjwt)
    await expect(result).rejects.toMatchObject({
      message: 'Status is not valid',
      code: 'STATUS_INVALID',
      details: { uri: 'https://example.com/status-list', idx: 1, status: 1 },
    })

    const safeResult = await sdjwt.safeVerify(encodedSdjwt)
    expect(safeResult.errors?.map((e) => e.code)).toEqual(['STATUS_INVALID'])
  })

  test('Test with a status list larger than maxStatusListDecompressedBytes', async () => {
    const { signer, verifier } = createSignerVerifier()
    // 1024 statuses of 1 bit inflate to 128 bytes
    const largeStatusListJWT = await signStatusList(statusListPrivateKey, new StatusList(new Array(1024).fill(0), 1), {
      sub: 'https://example.com/status-list',
      iat,
    })
    const createInstance = (maxStatusListDecompressedBytes: number) =>
      new SdJwtVcInstance({
        signer,
        signAlg: 'EdDSA',
        verifier,
        hasher: digest,
        hashAlg: 'sha-256',
        saltGenerator: generateSalt,
        statusListFetcher: () => Promise.resolve(largeStatusListJWT),
        statusVerifier: async (data: string, sig: string) =>
          Crypto.verify(null, Buffer.from(data), statusListPublicKey, Buffer.from(sig, 'base64url')),
        maxStatusListDecompressedBytes,
      })
    const encodedSdjwt = await createInstance(127).issue({
      iat,
      iss,
      vct,
      status: { status_list: { uri: 'https://example.com/status-list', idx: 6 } },
    })

    await expect(createInstance(127).verify(encodedSdjwt)).rejects.toThrow(
      'The status list is larger than the maximum of 127 bytes'
    )
    const safeResult = await createInstance(127).safeVerify(encodedSdjwt)
    expect(safeResult.errors?.map((e) => e.code)).toEqual(['STATUS_VERIFICATION_FAILED'])
    await expect(createInstance(128).verify(encodedSdjwt)).resolves.toBeDefined()
  })

  test('Test with a custom status validator', async () => {
    const statusValidator = vi.fn(async () => {})
    const { signer, verifier } = createSignerVerifier()
    const sdjwtWithValidator = new SdJwtVcInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
      statusListFetcher: () => Promise.resolve(statusListJWT),
      statusVerifier: async (data: string, sig: string) =>
        Crypto.verify(null, Buffer.from(data), statusListPublicKey, Buffer.from(sig, 'base64url')),
      statusValidator,
    })

    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct,
      status: { status_list: { uri: 'https://example.com/status-list', idx: 6 } },
    }
    await sdjwtWithValidator.verify(await sdjwtWithValidator.issue(expectedPayload))
    expect(statusValidator).toHaveBeenCalledWith(1, { uri: 'https://example.com/status-list', idx: 6 })
  })

  test('safeVerify reports a revoked credential as STATUS_INVALID', async () => {
    const claims = {
      firstname: 'John',
      status: {
        status_list: {
          uri: 'https://example.com/status-list',
          idx: 1,
        },
      },
    }
    const encodedSdjwt = await sdjwt.issue({ iat, iss, vct, ...claims })
    const result = await sdjwt.safeVerify(encodedSdjwt)

    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.errors.map((e) => e.code)).toEqual(['STATUS_INVALID'])
    }
  })

  test('safeVerify uses the error code from a custom status validator', async () => {
    const sdjwtWithValidator = new SdJwtVcInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
      statusListFetcher: () => Promise.resolve(statusListJWT),
      statusVerifier: async (data: string, sig: string) =>
        Crypto.verify(null, Buffer.from(data), statusListPublicKey, Buffer.from(sig, 'base64url')),
      statusValidator: async (status: number) => {
        if (status !== 0)
          throw new SdJwtError('Credential has been revoked', { details: { status }, code: 'STATUS_INVALID' })
      },
    })
    const claims = {
      firstname: 'John',
      status: {
        status_list: {
          uri: 'https://example.com/status-list',
          idx: 1,
        },
      },
    }
    const encodedSdjwt = await sdjwtWithValidator.issue({ iat, iss, vct, ...claims })
    const result = await sdjwtWithValidator.safeVerify(encodedSdjwt)

    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.errors.map((e) => e.code)).toEqual(['STATUS_INVALID'])
    }
  })

  test.each([
    [new SdJwtError('Type metadata does not match', { code: 'INVALID_VCT' }), 'INVALID_VCT'],
    [new Error('Type metadata could not be fetched'), 'VCT_VERIFICATION_FAILED'],
  ])('safeVerify keeps the code of a failed type metadata check: %s', async (error, expectedCode) => {
    const { signer, verifier } = createSignerVerifier()
    const sdjwtWithVct = new SdJwtVcInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
      loadTypeMetadataFormat: true,
      vctFetcher: async () => {
        throw error
      },
    })
    const encodedSdjwt = await sdjwtWithVct.issue({ iat, iss, vct, firstname: 'John' })
    const result = await sdjwtWithVct.safeVerify(encodedSdjwt)

    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.errors.map((e) => e.code)).toEqual([expectedCode])
    }
  })

  test('safeVerify fetches neither the status list nor the type metadata of a credential that failed verification', async () => {
    const statusListFetcher = vi.fn(async () => statusListJWT)
    const vctFetcher = vi.fn(async () => ({ vct }))
    const sdjwtWithFetchers = new SdJwtVcInstance({
      verifier,
      hasher: digest,
      statusListFetcher,
      loadTypeMetadataFormat: true,
      vctFetcher,
    })
    // Signed with a key the verifier does not trust, so the URIs in it are chosen by whoever signed it
    const { privateKey: untrustedKey } = Crypto.generateKeyPairSync('ed25519')
    const untrustedIssuer = new SdJwtVcInstance({
      signer: async (data: string) => Crypto.sign(null, Buffer.from(data), untrustedKey).toString('base64url'),
      signAlg: 'EdDSA',
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
    })
    const credential = await untrustedIssuer.issue({
      iat,
      iss,
      vct: 'http://169.254.169.254/latest/meta-data/',
      status: { status_list: { uri: 'http://10.0.0.1/admin', idx: 0 } },
    })

    const result = await sdjwtWithFetchers.safeVerify(credential)

    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.errors.map((e) => e.code)).toEqual(['INVALID_JWT_SIGNATURE'])
    }
    expect(statusListFetcher).not.toHaveBeenCalled()
    expect(vctFetcher).not.toHaveBeenCalled()
  })

  test('Test with a revoked credential but status verification disabled', async () => {
    const claims = {
      firstname: 'John',
      status: {
        status_list: {
          uri: 'https://example.com/status-list',
          idx: 1,
        },
      },
    }
    const expectedPayload: SdJwtVcPayload = { iat, iss, vct, ...claims }
    const encodedSdjwt = await sdjwt.issue(expectedPayload)
    const result = await sdjwt.verify(encodedSdjwt, {
      disableStatusVerification: true,
    })
    expect(result).toBeDefined()
  })

  test('Test with a status list token whose subject does not match the referenced uri', async () => {
    const claims = {
      firstname: 'John',
      status: {
        status_list: {
          uri: 'https://example.com/other-status-list',
          idx: 0,
        },
      },
    }
    const expectedPayload: SdJwtVcPayload = { iat, iss, vct, ...claims }
    const encodedSdjwt = await sdjwt.issue(expectedPayload)
    const result = sdjwt.verify(encodedSdjwt)
    await expect(result).rejects.toThrowError(
      "The 'sub' claim 'https://example.com/status-list' does not match the expected value 'https://example.com/other-status-list'"
    )
  })

  test('Test with a status list token whose typ header is not statuslist+jwt', async () => {
    const wrongTypStatusListJWT = await signStatusList(
      statusListPrivateKey,
      new StatusList([0, 0], 1),
      { iss: 'https://example.com', sub: 'https://example.com/status-list', iat },
      'JWT'
    )

    const { signer, verifier } = createSignerVerifier()
    const sdjwtWithWrongTyp = new SdJwtVcInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
      statusListFetcher: () => Promise.resolve(wrongTypStatusListJWT),
      statusVerifier: async (data: string, sig: string) =>
        Crypto.verify(null, Buffer.from(data), statusListPublicKey, Buffer.from(sig, 'base64url')),
    })

    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct,
      status: { status_list: { uri: 'https://example.com/status-list', idx: 0 } },
    }
    const encodedSdjwt = await sdjwtWithWrongTyp.issue(expectedPayload)
    const error = await sdjwtWithWrongTyp.verify(encodedSdjwt).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(JoseValidationError)
    expect((error as Error).message).toContain('typ: typ must be statuslist+jwt (invalid_typ)')
  })

  test('Test with the verifier used for the status list when no status verifier is provided', async () => {
    // the status list is signed with the same key as the credential
    const sameKeyStatusListJWT = await signStatusList(privateKey, new StatusList([0, 1], 1), {
      iss: 'https://example.com',
      sub: 'https://example.com/status-list',
      iat,
    })

    const { signer, verifier } = createSignerVerifier()
    const sdjwtWithoutStatusVerifier = new SdJwtVcInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
      statusListFetcher: () => Promise.resolve(sameKeyStatusListJWT),
    })

    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct,
      status: { status_list: { uri: 'https://example.com/status-list', idx: 0 } },
    }
    const encodedSdjwt = await sdjwtWithoutStatusVerifier.issue(expectedPayload)
    const result = await sdjwtWithoutStatusVerifier.verify(encodedSdjwt)
    expect(result).toBeDefined()
  })

  test('Test with the verification options passed to the status verifier', async () => {
    const { signer, verifier } = createSignerVerifier()
    // the key of the status list issuer is passed with the verification options
    const sdjwtWithKeyFromOptions = new SdJwtVcInstance<{ statusListKey: Crypto.KeyObject }>({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
      statusListFetcher: () => Promise.resolve(statusListJWT),
      statusVerifier: async (data, sig, options) => {
        if (!options) return false
        return Crypto.verify(null, Buffer.from(data), options.statusListKey, Buffer.from(sig, 'base64url'))
      },
    })

    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct,
      status: { status_list: { uri: 'https://example.com/status-list', idx: 0 } },
    }
    const encodedSdjwt = await sdjwtWithKeyFromOptions.issue(expectedPayload)
    await expect(
      sdjwtWithKeyFromOptions.verify(encodedSdjwt, { statusListKey: statusListPublicKey })
    ).resolves.toBeDefined()
  })

  test('test to fetch the statuslist', async () => {
    //TODO: not implemented yet since we need to either mock the fetcher or use a real fetcher
  })

  test('test with an expired status list', async () => {
    const expiredStatusListJWT = await signStatusList(statusListPrivateKey, new StatusList([0, 0], 1), {
      iss: 'https://example.com',
      sub: 'https://example.com/status-list',
      iat: 1000,
      exp: 2000,
    })

    const { signer, verifier } = createSignerVerifier()
    const sdjwtWithExpiredList = new SdJwtVcInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
      statusListFetcher: () => Promise.resolve(expiredStatusListJWT),
      statusVerifier: async (data: string, sig: string) =>
        Crypto.verify(null, Buffer.from(data), statusListPublicKey, Buffer.from(sig, 'base64url')),
    })

    const expectedPayload: SdJwtVcPayload = {
      iat: 1000,
      iss,
      vct,
      status: { status_list: { uri: 'https://example.com/status-list', idx: 0 } },
    }
    const encodedSdjwt = await sdjwtWithExpiredList.issue(expectedPayload)

    const error = await sdjwtWithExpiredList.verify(encodedSdjwt, { currentDate: 5000 }).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(StatusListError)
    expect(error).toMatchObject({
      message: 'Status List JWT verification failed: Verify Error: JWT is expired',
      details: { uri: 'https://example.com/status-list' },
    })

    // the rejected claim is on the original exception
    const cause = (error as { cause?: unknown }).cause
    expect(cause).toBeInstanceOf(JwtTimeClaimError)
    expect(cause).toMatchObject({
      code: 'JWT_EXPIRED',
      details: { claim: 'exp', value: 2000, currentDate: 5000, skewSeconds: 0 },
    })
  })
})

describe('Decode & Claims', () => {
  const { signer, verifier } = createSignerVerifier()
  const sdjwt = new SdJwtVcInstance({
    signer,
    signAlg: 'EdDSA',
    verifier,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  })

  test('decode should return typed SdJwtVcPayload with jti and aud', async () => {
    const payload: SdJwtVcPayload = {
      iat,
      iss,
      vct,
      aud: 'https://verifier.example.com',
      jti: 'urn:uuid:12345-67890',
      customClaim: 'value',
    }

    const encoded = await sdjwt.issue(payload)
    const decoded = await sdjwt.decode(encoded)

    expect(decoded.jwt?.payload).toBeDefined()
    const decodedPayload: SdJwtVcPayload | undefined = decoded.jwt?.payload
    expect(decodedPayload?.iss).toBe(iss)
    expect(decodedPayload?.vct).toBe(vct)
    expect(decodedPayload?.aud).toBe('https://verifier.example.com')
    expect(decodedPayload?.jti).toBe('urn:uuid:12345-67890')

    const claims = await sdjwt.getClaims(encoded)
    expect(claims.vct).toBe(vct)
    expect(claims.aud).toBe('https://verifier.example.com')
    expect(claims.jti).toBe('urn:uuid:12345-67890')
  })

  test('verify should validate expectedIssuer, expectedAudience, and expectedVct', async () => {
    const payload: SdJwtVcPayload = {
      iat,
      iss: 'https://issuer.example.com',
      vct: 'https://credentials.example.com/identity_credential',
      aud: 'https://verifier.example.com',
    }

    const encoded = await sdjwt.issue(payload)

    // Valid verification
    await expect(
      sdjwt.verify(encoded, {
        expectedIssuer: 'https://issuer.example.com',
        expectedAudience: 'https://verifier.example.com',
        expectedVct: 'https://credentials.example.com/identity_credential',
      })
    ).resolves.toBeDefined()

    // Invalid issuer
    await expect(
      sdjwt.verify(encoded, {
        expectedIssuer: 'https://other-issuer.example.com',
      })
    ).rejects.toThrow('Verify Error: Invalid issuer')

    // Invalid audience
    await expect(
      sdjwt.verify(encoded, {
        expectedAudience: 'https://other-verifier.example.com',
      })
    ).rejects.toThrow('Verify Error: Invalid audience')

    // Invalid vct
    await expect(
      sdjwt.verify(encoded, {
        expectedVct: 'https://other-vct.example.com',
      })
    ).rejects.toThrow('Verify Error: Invalid VCT')
  })
})
