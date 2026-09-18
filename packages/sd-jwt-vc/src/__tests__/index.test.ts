import Crypto from 'node:crypto'
import { hasher as digest, generateSalt } from '@owf/crypto'
import { createHeaderAndPayload, StatusList, type StatusListJWTHeaderParameters } from '@owf/token-status-list'
import type { DisclosureFrame, JwtPayload, Signer, Verifier } from '@sd-jwt/core'
import { SignJWT } from 'jose'
import { describe, expect, test } from 'vitest'
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
    await expect(result).rejects.toThrowError('Status is not valid')
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

  test('test to fetch the statuslist', async () => {
    //TODO: not implemented yet since we need to either mock the fetcher or use a real fetcher
  })

  test('test with an expired status list', async () => {
    //TODO: needs to be implemented
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
})
