import Crypto from 'node:crypto'
import { hasher as digest, generateSalt } from '@owf/crypto'
import type { DisclosureFrame, Signer, Verifier } from '@sd-jwt/core'
import { describe, expect, test } from 'vitest'
import { SDJwtVcInstance, type TypeMetadataFormat, verifyClaimsAgainstTypeMetadata } from '..'

const generateKeyPair = () => {
  const { publicKey, privateKey } = Crypto.generateKeyPairSync('ed25519')
  const signer: Signer = async (data: string) => {
    return Crypto.sign(undefined, Buffer.from(data), privateKey).toString('base64url')
  }

  const verifier: Verifier = async (data: string, signature: string) => {
    return Crypto.verify(undefined, Buffer.from(data), publicKey, Buffer.from(signature, 'base64url'))
  }

  return { signer, verifier }
}

const { signer, verifier } = generateKeyPair()

describe('SD-JWT VC Type Metadata Verification', () => {
  const pidTypeMetadata: TypeMetadataFormat = {
    vct: 'http://example.com/pid',
    name: 'Person Identification Data',
    claims: [
      { path: ['iss'], sd: 'never' },
      { path: ['vct'], sd: 'never' },
      { path: ['sub'], sd: 'never' },
      { path: ['given_name'], sd: 'always', mandatory: true },
      { path: ['family_name'], sd: 'always', mandatory: true },
      { path: ['birthdate'], sd: 'always' },
      { path: ['address'], sd: 'always' },
      { path: ['address', 'street_address'], sd: 'always' },
      { path: ['address', 'locality'], sd: 'always' },
      { path: ['nationalities'], sd: 'always' },
      { path: ['nationalities', null], sd: 'always' },
    ],
  }

  test('returns empty verification errors when presented VC matches type metadata perfectly', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    })

    const payload = {
      vct: 'http://example.com/pid',
      iss: 'https://issuer.example.com',
      sub: 'user-123',
      given_name: 'John',
      family_name: 'Doe',
      birthdate: '1990-01-01',
      address: {
        street_address: '123 Main St',
        locality: 'Springfield',
      },
      nationalities: ['US', 'DE'],
    }

    const disclosureFrame: DisclosureFrame<typeof payload> = {
      _sd: ['given_name', 'family_name', 'birthdate', 'nationalities', 'address'],
      address: {
        _sd: ['street_address', 'locality'],
      },
    }

    const compact = await sdJwtVc.issue(payload, disclosureFrame)
    const result = await sdJwtVc.verifyTypeMetadata(compact, pidTypeMetadata)

    expect(result.extraClaims).toEqual([])
    expect(result.missingMandatoryClaims).toEqual([])
    expect(result.invalidNonSelectivelyDisclosableClaims).toEqual([])
    expect(result.invalidSelectivelyDisclosableClaims).toEqual([])
  })

  test('detects extra claims not declared in type metadata', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    })

    const payload = {
      vct: 'http://example.com/pid',
      iss: 'https://issuer.example.com',
      sub: 'user-123',
      given_name: 'John',
      family_name: 'Doe',
      unlisted_claim: 'secret',
    }

    const disclosureFrame: DisclosureFrame<typeof payload> = {
      _sd: ['given_name', 'family_name', 'unlisted_claim'],
    }

    const compact = await sdJwtVc.issue(payload, disclosureFrame)
    const result = await sdJwtVc.verifyTypeMetadata(compact, pidTypeMetadata)

    expect(result.extraClaims).toEqual([['unlisted_claim']])
  })

  test('detects missing mandatory claims', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    })

    // Omits given_name which is mandatory in pidTypeMetadata
    const payload = {
      vct: 'http://example.com/pid',
      iss: 'https://issuer.example.com',
      sub: 'user-123',
      family_name: 'Doe',
    }

    const disclosureFrame: DisclosureFrame<typeof payload> = {
      _sd: ['family_name'],
    }

    const compact = await sdJwtVc.issue(payload, disclosureFrame)
    const result = await sdJwtVc.verifyTypeMetadata(compact, pidTypeMetadata)

    expect(result.missingMandatoryClaims).toEqual([['given_name']])
  })

  test('detects invalid non-selectively disclosable claims (presented plain when sd: "always" is required)', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    })

    // given_name is included in plain JWT payload, but metadata specifies sd: "always"
    const payload = {
      vct: 'http://example.com/pid',
      iss: 'https://issuer.example.com',
      sub: 'user-123',
      given_name: 'John',
      family_name: 'Doe',
    }

    const disclosureFrame: DisclosureFrame<typeof payload> = {
      _sd: ['family_name'],
    }

    const compact = await sdJwtVc.issue(payload, disclosureFrame)
    const result = await sdJwtVc.verifyTypeMetadata(compact, pidTypeMetadata)

    expect(result.invalidNonSelectivelyDisclosableClaims).toEqual([['given_name']])
  })

  test('detects invalid selectively disclosable claims (presented via disclosure when sd: "never" is required)', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    })

    // sub is disclosed via _sd, but metadata specifies sd: "never"
    const payload = {
      vct: 'http://example.com/pid',
      iss: 'https://issuer.example.com',
      sub: 'user-123',
      given_name: 'John',
      family_name: 'Doe',
    }

    const disclosureFrame: DisclosureFrame<typeof payload> = {
      _sd: ['given_name', 'family_name', 'sub'],
    }

    const compact = await sdJwtVc.issue(payload, disclosureFrame)
    const result = await sdJwtVc.verifyTypeMetadata(compact, pidTypeMetadata)

    expect(result.invalidSelectivelyDisclosableClaims).toEqual([['sub']])
  })

  test('automatically performs type metadata verification in verify and safeVerify when loadTypeMetadataFormat is configured', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
      loadTypeMetadataFormat: true,
      vctFetcher: async (vct) => {
        if (vct === 'http://example.com/pid') {
          return pidTypeMetadata
        }
        return undefined
      },
    })

    const payload = {
      vct: 'http://example.com/pid',
      iss: 'https://issuer.example.com',
      sub: 'user-123',
      given_name: 'John',
      family_name: 'Doe',
      extra_info: 'something',
    }

    const disclosureFrame: DisclosureFrame<typeof payload> = {
      _sd: ['given_name', 'family_name', 'extra_info'],
    }

    const compact = await sdJwtVc.issue(payload, disclosureFrame)

    const verifyRes = await sdJwtVc.verify(compact)
    expect(verifyRes.typeMetadata?.mergedTypeMetadata).toEqual(pidTypeMetadata)
    expect(verifyRes.typeMetadataVerification).toBeDefined()
    expect(verifyRes.typeMetadataVerification?.extraClaims).toEqual([['extra_info']])

    const safeVerifyRes = await sdJwtVc.safeVerify(compact)
    expect(safeVerifyRes.success).toBe(true)
    if (safeVerifyRes.success) {
      expect(safeVerifyRes.data.typeMetadataVerification?.extraClaims).toEqual([['extra_info']])
    }
  })

  test('verifies nested objects and array element claims correctly with verifyClaimsAgainstTypeMetadata', () => {
    const metadata: TypeMetadataFormat = {
      vct: 'http://example.com/nested',
      claims: [
        { path: ['user', 'name'], sd: 'always' },
        { path: ['user', 'roles', null], sd: 'always' },
      ],
    }

    const unpackedObj = {
      vct: 'http://example.com/nested',
      user: {
        name: 'Alice',
        roles: ['admin', 'user'],
      },
    }

    // disclosureKeymap has user.name and user.roles.0
    const disclosureKeymap = {
      'user.name': 'hash1',
      'user.roles.0': 'hash2',
      'user.roles.1': 'hash3',
    }

    const res = verifyClaimsAgainstTypeMetadata(metadata, unpackedObj, disclosureKeymap)
    expect(res.extraClaims).toEqual([['vct'], ['user'], ['user', 'roles']])
    expect(res.missingMandatoryClaims).toEqual([])
    expect(res.invalidNonSelectivelyDisclosableClaims).toEqual([])
    expect(res.invalidSelectivelyDisclosableClaims).toEqual([])
  })

  test('respects extended type metadata inheritance chain during verify and safeVerify', async () => {
    const baseMetadata: TypeMetadataFormat = {
      vct: 'http://example.com/base-identity',
      name: 'Base Identity',
      claims: [
        { path: ['iss'], sd: 'never' },
        { path: ['vct'], sd: 'never' },
        { path: ['given_name'], sd: 'always', mandatory: true },
        { path: ['family_name'], sd: 'always', mandatory: true },
      ],
    }

    const extendingMetadata: TypeMetadataFormat = {
      vct: 'http://example.com/employee-credential',
      name: 'Employee Credential',
      extends: 'http://example.com/base-identity',
      claims: [
        { path: ['employee_id'], sd: 'always', mandatory: true },
        { path: ['department'], sd: 'always' },
      ],
    }

    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
      loadTypeMetadataFormat: true,
      vctFetcher: async (vct) => {
        if (vct === 'http://example.com/employee-credential') {
          return extendingMetadata
        }
        if (vct === 'http://example.com/base-identity') {
          return baseMetadata
        }
        return undefined
      },
    })

    // Valid credential with claims from both base and extending metadata
    const payload = {
      vct: 'http://example.com/employee-credential',
      iss: 'https://issuer.example.com',
      given_name: 'Alice',
      family_name: 'Smith',
      employee_id: 'EMP-001',
    }

    const compact = await sdJwtVc.issue(payload, {
      _sd: ['given_name', 'family_name', 'employee_id'],
    })

    const verifyRes = await sdJwtVc.verify(compact)
    expect(verifyRes.typeMetadata?.typeMetadataChain).toHaveLength(2)
    expect(verifyRes.typeMetadata?.mergedTypeMetadata.claims).toHaveLength(6)
    expect(verifyRes.typeMetadataVerification).toEqual({
      extraClaims: [],
      missingMandatoryClaims: [],
      invalidNonSelectivelyDisclosableClaims: [],
      invalidSelectivelyDisclosableClaims: [],
    })

    // Missing mandatory claim from base metadata (family_name)
    const missingBasePayload = {
      vct: 'http://example.com/employee-credential',
      iss: 'https://issuer.example.com',
      given_name: 'Alice',
      employee_id: 'EMP-001',
    }
    const missingBaseCompact = await sdJwtVc.issue(missingBasePayload, {
      _sd: ['given_name', 'employee_id'],
    })
    const missingBaseRes = await sdJwtVc.verify(missingBaseCompact)
    expect(missingBaseRes.typeMetadataVerification?.missingMandatoryClaims).toEqual([['family_name']])

    // Direct verifyTypeMetadata call with unmerged extending metadata resolves the chain
    const directVerifyRes = await sdJwtVc.verifyTypeMetadata(compact, extendingMetadata)
    expect(directVerifyRes).toEqual({
      extraClaims: [],
      missingMandatoryClaims: [],
      invalidNonSelectivelyDisclosableClaims: [],
      invalidSelectivelyDisclosableClaims: [],
    })
  })
})
