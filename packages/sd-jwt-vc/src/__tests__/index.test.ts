import Crypto from 'node:crypto'
import { hasher as digest, generateSalt } from '@owf/crypto'
import {
  createHeaderAndPayload,
  SLException,
  StatusList,
  type StatusListJWTHeaderParameters,
} from '@owf/token-status-list'
import {
  type DisclosureFrame,
  type JwtPayload,
  JwtTimeClaimException,
  SDJWTException,
  type Signer,
  type Verifier,
} from '@sd-jwt/core'
import { SignJWT } from 'jose'
import { describe, expect, test, vi } from 'vitest'
import { SDJwtVcInstance } from '..'
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

const generateStatusList = async (): Promise<string> => {
  const statusList = new StatusList([0, 1, 0, 0, 0, 0, 1, 1], 1)
  const payload: JwtPayload = {
    iss: 'https://example.com',
    sub: 'https://example.com/status-list',
    iat: Math.floor(Date.now() / 1000),
  }
  const header: StatusListJWTHeaderParameters = {
    alg: 'EdDSA',
    typ: 'statuslist+jwt',
  }
  const values = createHeaderAndPayload(statusList, payload, header)
  return new SignJWT(values.payload).setProtectedHeader(values.header).sign(statusListPrivateKey)
}

const statusListJWT = await generateStatusList()

describe('App', () => {
  test('Example', async () => {
    const { signer, verifier } = createSignerVerifier()
    const sdjwt = new SDJwtVcInstance({
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
})

describe('Revocation', () => {
  const { signer, verifier } = createSignerVerifier()
  const sdjwt = new SDJwtVcInstance({
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

  test('Test with a custom status validator', async () => {
    const statusValidator = vi.fn(async () => {})
    const { signer, verifier } = createSignerVerifier()
    const sdjwtWithValidator = new SDJwtVcInstance({
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
    const sdjwtWithValidator = new SDJwtVcInstance({
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
          throw new SDJWTException('Credential has been revoked', { details: { status }, code: 'STATUS_INVALID' })
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
    [new SDJWTException('Type metadata does not match', { code: 'INVALID_VCT' }), 'INVALID_VCT'],
    [new Error('Type metadata could not be fetched'), 'VCT_VERIFICATION_FAILED'],
  ])('safeVerify keeps the code of a failed type metadata check: %s', async (error, expectedCode) => {
    const { signer, verifier } = createSignerVerifier()
    const sdjwtWithVct = new SDJwtVcInstance({
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
      "The subject claim 'https://example.com/status-list' must be equal to the uri 'https://example.com/other-status-list'"
    )
  })

  test('Test with a status list token whose typ header is not statuslist+jwt', async () => {
    const { header, payload } = createHeaderAndPayload(
      new StatusList([0, 0], 1),
      { iss: 'https://example.com', sub: 'https://example.com/status-list', iat },
      { alg: 'EdDSA', typ: 'statuslist+jwt' }
    )
    // `createHeaderAndPayload` always sets the typ, so the wrong typ is set on the protected header instead
    const wrongTypStatusListJWT = await new SignJWT(payload)
      .setProtectedHeader({ ...header, typ: 'JWT' })
      .sign(statusListPrivateKey)

    const { signer, verifier } = createSignerVerifier()
    const sdjwtWithWrongTyp = new SDJwtVcInstance({
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
    await expect(sdjwtWithWrongTyp.verify(encodedSdjwt)).rejects.toThrowError(
      "The typ header 'JWT' must be equal to 'statuslist+jwt'"
    )
  })

  test('Test with the verifier used for the status list when no status verifier is provided', async () => {
    // the status list is signed with the same key as the credential
    const statusList = new StatusList([0, 1], 1)
    const { header, payload } = createHeaderAndPayload(
      statusList,
      { iss: 'https://example.com', sub: 'https://example.com/status-list', iat },
      { alg: 'EdDSA', typ: 'statuslist+jwt' }
    )
    const sameKeyStatusListJWT = await new SignJWT(payload).setProtectedHeader(header).sign(privateKey)

    const { signer, verifier } = createSignerVerifier()
    const sdjwtWithoutStatusVerifier = new SDJwtVcInstance({
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
    const sdjwtWithKeyFromOptions = new SDJwtVcInstance<{ statusListKey: Crypto.KeyObject }>({
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
    const { header, payload } = createHeaderAndPayload(
      new StatusList([0, 0], 1),
      { iss: 'https://example.com', sub: 'https://example.com/status-list', iat: 1000, exp: 2000 },
      { alg: 'EdDSA', typ: 'statuslist+jwt' }
    )
    const expiredStatusListJWT = await new SignJWT(payload).setProtectedHeader(header).sign(statusListPrivateKey)

    const { signer, verifier } = createSignerVerifier()
    const sdjwtWithExpiredList = new SDJwtVcInstance({
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
    expect(error).toBeInstanceOf(SLException)
    expect(error).toMatchObject({
      message: 'Status List JWT verification failed: Verify Error: JWT is expired',
      details: { uri: 'https://example.com/status-list' },
    })

    // the rejected claim is on the original exception
    const cause = (error as { cause?: unknown }).cause
    expect(cause).toBeInstanceOf(JwtTimeClaimException)
    expect(cause).toMatchObject({
      code: 'JWT_EXPIRED',
      details: { claim: 'exp', value: 2000, currentDate: 5000, skewSeconds: 0 },
    })
  })
})

describe('Decode & Claims', () => {
  const { signer, verifier } = createSignerVerifier()
  const sdjwt = new SDJwtVcInstance({
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
