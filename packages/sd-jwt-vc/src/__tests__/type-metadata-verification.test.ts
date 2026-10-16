import Crypto from 'node:crypto'
import { hasher as digest, generateSalt } from '@owf/crypto'
import { createHashMapping, type DisclosureFrame, SDJwt, type Signer, type Verifier } from '@sd-jwt/core'
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
      nationalities: {
        _sd: [0, 1],
      },
    }

    const compact = await sdJwtVc.issue(payload, disclosureFrame)
    const result = await sdJwtVc.verifyTypeMetadata(compact, pidTypeMetadata)

    expect(result.extraClaims).toEqual([])
    expect(result.missingMandatoryClaims).toEqual([])
    expect(result.undisclosedMandatoryClaims).toEqual([])
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

  test('reports absent mandatory claims that may be selectively disclosable as undisclosed', async () => {
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

    expect(result.missingMandatoryClaims).toEqual([])
    expect(result.undisclosedMandatoryClaims).toEqual([['given_name']])
  })

  test('reports mandatory claims withheld in a presentation as undisclosed', async () => {
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
    }

    const compact = await sdJwtVc.issue(payload, { _sd: ['given_name', 'family_name'] })
    const presentation = await sdJwtVc.present<typeof payload>(compact, { given_name: true })
    const result = await sdJwtVc.verifyTypeMetadata(presentation, pidTypeMetadata)

    expect(result.missingMandatoryClaims).toEqual([])
    expect(result.undisclosedMandatoryClaims).toEqual([['family_name']])
  })

  test('detects missing mandatory claims that must not be selectively disclosable', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    })

    const metadata: TypeMetadataFormat = {
      vct: 'urn:x',
      claims: [
        { path: ['vct'] },
        { path: ['iss'] },
        { path: ['document_number'], sd: 'never', mandatory: true },
        { path: ['address'], sd: 'always' },
        { path: ['address', 'country'], sd: 'never', mandatory: true },
      ],
    }

    const compact = await sdJwtVc.issue({ vct: 'urn:x', iss: 'https://issuer.example.com' })
    const result = await sdJwtVc.verifyTypeMetadata(compact, metadata)

    expect(result.missingMandatoryClaims).toEqual([['document_number']])
    // The address may have been withheld, so the country can't be missing
    expect(result.undisclosedMandatoryClaims).toEqual([['address', 'country']])
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

  test('verifies nested objects and array element claims correctly with verifyClaimsAgainstTypeMetadata', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    })

    const metadata: TypeMetadataFormat = {
      vct: 'http://example.com/nested',
      claims: [
        { path: ['user', 'name'], sd: 'always' },
        { path: ['user', 'roles', null], sd: 'always' },
      ],
    }

    const payload = {
      vct: 'http://example.com/nested',
      iss: 'https://issuer.example.com',
      user: {
        name: 'Alice',
        roles: ['admin', 'user'],
      },
    }

    const compact = await sdJwtVc.issue(payload, { user: { _sd: ['name'], roles: { _sd: [0, 1] } } })
    const sdjwt = await SDJwt.fromEncode(compact, digest)
    const disclosures = await createHashMapping(sdjwt.disclosures ?? [], { hasher: digest, alg: 'sha-256' })

    const res = verifyClaimsAgainstTypeMetadata(metadata, sdjwt.jwt?.payload ?? {}, disclosures)
    // `vct` and `iss` are registered claims, `user` and `user.roles` are ancestors of declared claims
    expect(res).toEqual({
      extraClaims: [],
      missingMandatoryClaims: [],
      undisclosedMandatoryClaims: [],
      invalidNonSelectivelyDisclosableClaims: [],
      invalidSelectivelyDisclosableClaims: [],
    })
  })

  test('reports only the topmost undeclared claim and covers descendants of declared leaf claims', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    })

    const metadata: TypeMetadataFormat = {
      vct: 'urn:x',
      claims: [{ path: ['cnf'] }, { path: ['address'] }, { path: ['address', 'street'] }],
    }

    const compact = await sdJwtVc.issue({
      vct: 'urn:x',
      iss: 'https://issuer.example.com',
      iat: 1700000000,
      cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: 'abc' } },
      address: { street: 'Main St', geo: { lat: 1, lng: 2 } },
      extra: { nested: { deep: true } },
    })
    const result = await sdJwtVc.verifyTypeMetadata(compact, metadata)

    expect(result.extraClaims).toEqual([['address', 'geo'], ['extra']])
  })

  test('detects sd: "always" violations on elements of a partially presented array', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    })

    const metadata: TypeMetadataFormat = {
      vct: 'urn:x',
      claims: [
        { path: ['vct'] },
        { path: ['iss'] },
        { path: ['nat'] },
        { path: ['nat', null], sd: 'always' },
        { path: ['items'] },
        { path: ['items', null] },
        { path: ['items', null, 'name'], sd: 'always' },
      ],
    }
    const payload = {
      vct: 'urn:x',
      iss: 'https://issuer.example.com',
      nat: ['US', 'DE'],
      items: [{ name: 'a' }, { name: 'b' }],
    }

    const compact = await sdJwtVc.issue(payload, {
      nat: { _sd: [0, 1] },
      items: { _sd: [0, 1], 0: { _sd: ['name'] }, 1: { _sd: ['name'] } },
    })
    const presentation = await sdJwtVc.present<typeof payload>(compact, {
      nat: { 1: true },
      items: { 1: { name: true } },
    })
    const presentedResult = await sdJwtVc.verifyTypeMetadata(presentation, metadata)
    expect(presentedResult.invalidNonSelectivelyDisclosableClaims).toEqual([])

    // 'US' is a plain claim, while 'DE' is selectively disclosable
    const mixedCompact = await sdJwtVc.issue(payload, { nat: { _sd: [1] } })
    const mixedResult = await sdJwtVc.verifyTypeMetadata(mixedCompact, metadata)
    expect(mixedResult.invalidNonSelectivelyDisclosableClaims).toEqual([
      ['nat', null],
      ['items', null, 'name'],
    ])
  })

  test('detects sd: "never" violations on elements of an array', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    })

    const metadata: TypeMetadataFormat = {
      vct: 'urn:x',
      claims: [{ path: ['nat'] }, { path: ['nat', null], sd: 'never' }],
    }

    const compact = await sdJwtVc.issue({ vct: 'urn:x', nat: ['US', 'DE'] }, { nat: { _sd: [1] } })
    const result = await sdJwtVc.verifyTypeMetadata(compact, metadata)
    expect(result.invalidSelectivelyDisclosableClaims).toEqual([['nat', null]])
  })

  test('treats plain children of a selectively disclosed parent as not selectively disclosable', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    })

    const metadata: TypeMetadataFormat = {
      vct: 'urn:x',
      claims: [
        { path: ['vct'] },
        { path: ['iss'] },
        { path: ['address'], sd: 'always' },
        { path: ['address', 'country'], sd: 'never' },
        { path: ['address', 'street'], sd: 'always' },
      ],
    }
    const payload = { vct: 'urn:x', iss: 'https://issuer.example.com', address: { country: 'DE', street: 'Main St' } }
    const compact = await sdJwtVc.issue(payload, { _sd: ['address'] })

    const result = await sdJwtVc.verifyTypeMetadata(compact, metadata)
    expect(result.invalidSelectivelyDisclosableClaims).toEqual([])
    expect(result.invalidNonSelectivelyDisclosableClaims).toEqual([['address', 'street']])
  })

  test('does not treat digit-only object keys as array indices', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    })

    const metadata: TypeMetadataFormat = {
      vct: 'urn:x',
      claims: [{ path: ['vct'] }, { path: ['iss'] }, { path: ['scores'] }, { path: ['scores', '2023'] }],
    }
    const compact = await sdJwtVc.issue({ vct: 'urn:x', iss: 'https://issuer.example.com', scores: { '2023': 5 } })

    const result = await sdJwtVc.verifyTypeMetadata(compact, metadata)
    expect(result.extraClaims).toEqual([])
  })

  test('rejects type metadata for a different vct', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    })

    const compact = await sdJwtVc.issue({ vct: 'urn:x', iss: 'https://issuer.example.com' })
    await expect(sdJwtVc.verifyTypeMetadata(compact, { vct: 'urn:other', claims: [] })).rejects.toThrow(
      "Type metadata vct 'urn:other' does not match the vct 'urn:x' of the SD-JWT VC"
    )
    await expect(
      sdJwtVc.verifyTypeMetadata(compact, {
        mergedTypeMetadata: { vct: 'urn:other' },
        typeMetadataChain: [{ vct: 'urn:other' }],
        vctValues: ['urn:other'],
      })
    ).rejects.toThrow("Type metadata vct 'urn:other' does not match")
  })

  test('does not report a duplicate error in safeVerify when the SD-JWT is invalid', async () => {
    const sdJwtVc = new SDJwtVcInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
      loadTypeMetadataFormat: true,
      vctFetcher: async () => ({ vct: 'urn:x', claims: [] }),
    })

    const compact = await sdJwtVc.issue(
      { vct: 'urn:x', iss: 'https://issuer.example.com', name: 'a' },
      { _sd: ['name'] }
    )
    const other = await sdJwtVc.issue({ vct: 'urn:x', iss: 'https://issuer.example.com', name: 'b' }, { _sd: ['name'] })
    // Add a disclosure that the payload does not reference
    const [, otherDisclosure] = other.split('~')
    const tampered = compact.replace(/~$/, `~${otherDisclosure}~`)

    const result = await sdJwtVc.safeVerify(tampered)
    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.errors.filter((e) => e.message.includes('Unreferenced disclosure'))).toHaveLength(1)
    }
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
      undisclosedMandatoryClaims: [],
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
    expect(missingBaseRes.typeMetadataVerification?.undisclosedMandatoryClaims).toEqual([['family_name']])

    // Direct verifyTypeMetadata call with unmerged extending metadata resolves the chain
    const directVerifyRes = await sdJwtVc.verifyTypeMetadata(compact, extendingMetadata)
    expect(directVerifyRes).toEqual({
      extraClaims: [],
      missingMandatoryClaims: [],
      undisclosedMandatoryClaims: [],
      invalidNonSelectivelyDisclosableClaims: [],
      invalidSelectivelyDisclosableClaims: [],
    })
  })
})
