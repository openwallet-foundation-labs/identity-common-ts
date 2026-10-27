import Crypto from 'node:crypto'
import { hasher as digest, generateSalt, integrity } from '@owf/crypto'
import type { DisclosureFrame, Signer, Verifier } from '@sd-jwt/core'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test, vitest } from 'vitest'
import { SDJwtVcInstance } from '..'
import type { SdJwtVcPayload } from '../sd-jwt-vc-payload'
import type { TypeMetadataFormat } from '../sd-jwt-vc-type-metadata-format'

const exampleVctm = {
  vct: 'http://example.com/example',
  name: 'ExampleCredentialType',
  description: 'An example credential type',
}

const baseVctm: TypeMetadataFormat = {
  vct: 'http://example.com/base',
  name: 'BaseCredentialType',
  description: 'A base credential type',
  claims: [
    {
      path: ['firstName'],
      display: [{ locale: 'en', label: 'First Name' }],
    },
  ],
  display: [
    {
      locale: 'en',
      name: 'Base Credential',
      description: 'Base description',
    },
  ],
}

const extendingVctm: TypeMetadataFormat = {
  vct: 'http://example.com/extending',
  name: 'ExtendingCredentialType',
  description: 'A credential type that extends the base',
  extends: 'http://example.com/base',
  claims: [
    {
      path: ['lastName'],
      display: [{ locale: 'en', label: 'Last Name' }],
    },
  ],
  display: [
    {
      locale: 'en',
      name: 'Extended Credential',
      description: 'Extended description',
    },
    {
      locale: 'de',
      name: 'Erweiterte Berechtigung',
      description: 'Erweiterte Beschreibung',
    },
  ],
}

const middleVctm: TypeMetadataFormat = {
  vct: 'http://example.com/middle',
  name: 'MiddleCredentialType',
  description: 'Middle type in chain',
  extends: 'http://example.com/extending',
  claims: [
    {
      path: ['age'],
      display: [{ locale: 'en', label: 'Age' }],
    },
  ],
}

const overridingVctm: TypeMetadataFormat = {
  vct: 'http://example.com/overriding',
  name: 'OverridingCredentialType',
  description: 'A credential type that overrides a claim from the base',
  extends: 'http://example.com/base',
  claims: [
    {
      path: ['firstName'],
      display: [{ locale: 'en', label: 'Given Name' }], // Override with different label
      sd: 'always' as const,
    },
    {
      path: ['middleName'],
      display: [{ locale: 'en', label: 'Middle Name' }],
    },
  ],
}

const circularVctm: TypeMetadataFormat = {
  vct: 'http://example.com/circular',
  name: 'CircularCredentialType',
  extends: 'http://example.com/circular',
}

const cycleStartVctm: TypeMetadataFormat = {
  vct: 'http://example.com/cycle-start',
  name: 'CycleStartCredentialType',
  extends: 'http://example.com/cycle-end',
}

const cycleEndVctm: TypeMetadataFormat = {
  vct: 'http://example.com/cycle-end',
  name: 'CycleEndCredentialType',
  extends: 'http://example.com/cycle-start',
}

const deepVctm: TypeMetadataFormat = {
  vct: 'http://example.com/deep',
  name: 'DeepCredentialType',
  extends: 'http://example.com/middle',
}

const baseWithSdAlways: TypeMetadataFormat = {
  vct: 'http://example.com/base-sd-always',
  name: 'BaseWithSdAlways',
  claims: [
    {
      path: ['sensitiveData'],
      sd: 'always' as const,
      display: [{ locale: 'en', label: 'Sensitive Data' }],
    },
  ],
}

const invalidExtendingSdChange: TypeMetadataFormat = {
  vct: 'http://example.com/invalid-sd-change',
  name: 'InvalidSdChange',
  extends: 'http://example.com/base-sd-always',
  claims: [
    {
      path: ['sensitiveData'],
      sd: 'never' as const, // Invalid: trying to change from 'always' to 'never'
      display: [{ locale: 'en', label: 'Sensitive Data' }],
    },
  ],
}

const validExtendingSdChange: TypeMetadataFormat = {
  vct: 'http://example.com/valid-sd-change',
  name: 'ValidSdChange',
  extends: 'http://example.com/base',
  claims: [
    {
      path: ['firstName'],
      sd: 'always' as const, // Valid: base doesn't have sd or has 'allowed'
      display: [{ locale: 'en', label: 'First Name' }],
    },
  ],
}

const vctWithCustomProperties: TypeMetadataFormat = {
  vct: 'http://example.com/custom-properties',
  name: 'CustomProperties',
  claims: [
    {
      path: ['firstName'],
      sd: 'always' as const, // Valid: base doesn't have sd or has 'allowed'
      display: [{ locale: 'en', label: 'First Name' }],
      anotherCustom: 'property',
    },
  ],
  test: 'something',
}

const restHandlers = [
  http.get('http://example.com/example', () => {
    const res: TypeMetadataFormat = exampleVctm
    return HttpResponse.json(res)
  }),
  http.get('http://example.com/timeout', () => {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve(HttpResponse.json({}))
      }, 10000)
    })
  }),
  http.get('http://example.com/base', () => {
    return HttpResponse.json(baseVctm)
  }),
  http.get('http://example.com/extending', () => {
    return HttpResponse.json(extendingVctm)
  }),
  http.get('http://example.com/middle', () => {
    return HttpResponse.json(middleVctm)
  }),
  http.get('http://example.com/overriding', () => {
    return HttpResponse.json(overridingVctm)
  }),
  http.get('http://example.com/circular', () => {
    return HttpResponse.json(circularVctm)
  }),
  http.get('http://example.com/cycle-start', () => {
    return HttpResponse.json(cycleStartVctm)
  }),
  http.get('http://example.com/cycle-end', () => {
    return HttpResponse.json(cycleEndVctm)
  }),
  http.get('http://example.com/other-type', () => {
    // Describes another type than the one it is served for
    return HttpResponse.json({ ...baseVctm, vct: 'urn:eudi:pid:1' })
  }),
  http.get('http://example.com/extends-other-type', () => {
    return HttpResponse.json({
      ...extendingVctm,
      vct: 'http://example.com/extends-other-type',
      extends: 'http://example.com/other-type',
    })
  }),
  http.get('http://example.com/deep', () => {
    return HttpResponse.json(deepVctm)
  }),
  http.get('http://example.com/base-sd-always', () => {
    return HttpResponse.json(baseWithSdAlways)
  }),
  http.get('http://example.com/invalid-sd-change', () => {
    return HttpResponse.json(invalidExtendingSdChange)
  }),
  http.get('http://example.com/valid-sd-change', () => {
    return HttpResponse.json(validExtendingSdChange)
  }),
  http.get('http://example.com/custom-properties', () => {
    return HttpResponse.json(vctWithCustomProperties)
  }),
  http.get('http://example.com/invalid', () => {
    // Return invalid type metadata (missing required 'vct' field)
    return HttpResponse.json({
      name: 'InvalidCredentialType',
      description: 'Missing required vct field',
    })
  }),
]

const vctIntegrity = integrity(JSON.stringify(exampleVctm))

const server = setupServer(...restHandlers)

const iss = 'ExampleIssuer'
const vct = 'http://example.com/example'
const iat = Math.floor(Date.now() / 1000) // current time in seconds

const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519')

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

describe('App', () => {
  const { signer, verifier } = createSignerVerifier()

  const sdjwt = new SDJwtVcInstance({
    signer,
    signAlg: 'EdDSA',
    verifier,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
    loadTypeMetadataFormat: true,
    timeout: 1000,
  })

  const claims = {
    firstname: 'John',
  }
  const disclosureFrame = {
    _sd: ['firstname'],
  }

  beforeAll(() => server.listen({ onUnhandledRequest: 'warn' }))

  afterAll(() => server.close())

  afterEach(() => server.resetHandlers())

  test('VCT Validation', async () => {
    const validateIntegritySpy = vitest.spyOn(sdjwt, 'validateIntegrity')

    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct,
      'vct#integrity': vctIntegrity,
      ...claims,
    }

    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    await sdjwt.verify(encodedSdjwt)

    // Ensure validateIntegrity method was called
    expect(validateIntegritySpy).toHaveBeenCalledWith(expect.any(Response), vct, vctIntegrity)
  })

  describe('VCT integrity', () => {
    const issueWithIntegrity = (vctIntegrity: string) => {
      const payload: SdJwtVcPayload = { iat, iss, vct, 'vct#integrity': vctIntegrity, ...claims }
      return sdjwt.issue(payload, disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>)
    }
    const body = JSON.stringify(exampleVctm)
    const wrongSha256 = integrity('other', 'sha256')

    test('accepts a base64 encoded digest', async () => {
      const result = await sdjwt.verify(await issueWithIntegrity(integrity(body, 'sha256')))
      expect(result.typeMetadata?.mergedTypeMetadata.vct).toBe(vct)
    })

    test('rejects a digest that does not match', async () => {
      await expect(sdjwt.verify(await issueWithIntegrity(wrongSha256))).rejects.toThrowError(
        `Integrity check for ${vct} failed`
      )
    })

    test('rejects the hex encoded digest', async () => {
      const hex = Array.from(digest(body, 'sha256'), (byte) => byte.toString(16).padStart(2, '0')).join('')
      await expect(sdjwt.verify(await issueWithIntegrity(`sha256-${hex}`))).rejects.toThrowError(
        `Integrity check for ${vct} failed`
      )
    })

    test('only checks the strongest algorithm', async () => {
      await expect(
        sdjwt.verify(await issueWithIntegrity(`${wrongSha256} ${integrity(body, 'sha512')}`))
      ).resolves.toBeDefined()
      await expect(
        sdjwt.verify(await issueWithIntegrity(`${integrity(body, 'sha256')} ${integrity('other', 'sha384')}`))
      ).rejects.toThrowError(`Integrity check for ${vct} failed`)
    })

    test('accepts any value of the strongest algorithm and ignores options', async () => {
      const result = await sdjwt.verify(
        await issueWithIntegrity(`${integrity('other', 'sha384')} ${integrity(body, 'sha384')}?foo=bar`)
      )
      expect(result.typeMetadata).toBeDefined()
    })

    test('rejects integrity metadata without a supported algorithm', async () => {
      await expect(sdjwt.verify(await issueWithIntegrity('md5-abc'))).rejects.toThrowError(
        `Integrity check for ${vct} failed: no supported algorithm in md5-abc`
      )
    })
  })

  test('VCT Validation with timeout', async () => {
    const vct = 'http://example.com/timeout'
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct,
      ...claims,
    }
    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    await expect(sdjwt.verify(encodedSdjwt)).rejects.toThrowError(`Request to ${vct} timed out`)
  })

  test('VCT Metadata retrieval', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct,
      'vct#Integrity': vctIntegrity,
      ...claims,
    }
    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    const resolvedTypeMetadata = await sdjwt.getVct(encodedSdjwt)

    // Check mergedTypeMetadata
    expect(resolvedTypeMetadata?.mergedTypeMetadata).to.deep.eq({
      description: 'An example credential type',
      name: 'ExampleCredentialType',
      vct: 'http://example.com/example',
    })

    // Check typeMetadataChain - should have only one document (no extends)
    expect(resolvedTypeMetadata?.typeMetadataChain).toHaveLength(1)
    expect(resolvedTypeMetadata?.typeMetadataChain[0].vct).toBe('http://example.com/example')

    // Check vctValues - should have only one value
    expect(resolvedTypeMetadata?.vctValues).toHaveLength(1)
    expect(resolvedTypeMetadata?.vctValues[0]).toBe('http://example.com/example')
  })

  test('VCT Metadata retrieval fails when fetched type metadata is invalid', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct: 'http://example.com/invalid',
      ...claims,
    }
    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    await expect(sdjwt.getVct(encodedSdjwt)).rejects.toThrowError()
  })

  test('VCT with extends - simple chain', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct: 'http://example.com/extending',
      ...claims,
    }

    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    const resolvedTypeMetadata = await sdjwt.getVct(encodedSdjwt)

    // Check mergedTypeMetadata - should merge claims from both base and extending types
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims).toHaveLength(2)
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims?.[0].path).toEqual(['firstName'])
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims?.[1].path).toEqual(['lastName'])

    // Display from extending type completely replaces base display (section 8.2)
    expect(resolvedTypeMetadata?.mergedTypeMetadata.display).toHaveLength(2)
    expect(resolvedTypeMetadata?.mergedTypeMetadata.display?.[0]).toEqual({
      locale: 'en',
      name: 'Extended Credential',
      description: 'Extended description',
    })
    expect(resolvedTypeMetadata?.mergedTypeMetadata.display?.[1]).toEqual({
      locale: 'de',
      name: 'Erweiterte Berechtigung',
      description: 'Erweiterte Beschreibung',
    })

    // Top-level properties should come from extending type
    expect(resolvedTypeMetadata?.mergedTypeMetadata.name).toBe('ExtendingCredentialType')
    expect(resolvedTypeMetadata?.mergedTypeMetadata.description).toBe('A credential type that extends the base')

    // Check typeMetadataChain - should have 2 documents in chain
    expect(resolvedTypeMetadata?.typeMetadataChain).toHaveLength(2)
    expect(resolvedTypeMetadata?.typeMetadataChain[0].vct).toBe('http://example.com/extending')
    expect(resolvedTypeMetadata?.typeMetadataChain[1].vct).toBe('http://example.com/base')

    // Check vctValues - should have 2 values
    expect(resolvedTypeMetadata?.vctValues).toHaveLength(2)
    expect(resolvedTypeMetadata?.vctValues[0]).toBe('http://example.com/extending')
    expect(resolvedTypeMetadata?.vctValues[1]).toBe('http://example.com/base')
  })

  test('VCT with extends - multi-level chain', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct: 'http://example.com/middle',
      ...claims,
    }

    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    const resolvedTypeMetadata = await sdjwt.getVct(encodedSdjwt)

    // Check mergedTypeMetadata - should merge claims from base -> extending -> middle
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims).toHaveLength(3)
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims?.[0].path).toEqual(['firstName'])
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims?.[1].path).toEqual(['lastName'])
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims?.[2].path).toEqual(['age'])

    // Top-level properties should come from the most derived type
    expect(resolvedTypeMetadata?.mergedTypeMetadata.name).toBe('MiddleCredentialType')
    expect(resolvedTypeMetadata?.mergedTypeMetadata.description).toBe('Middle type in chain')

    // Check typeMetadataChain - should have 3 documents in chain
    expect(resolvedTypeMetadata?.typeMetadataChain).toHaveLength(3)
    expect(resolvedTypeMetadata?.typeMetadataChain[0].vct).toBe('http://example.com/middle')
    expect(resolvedTypeMetadata?.typeMetadataChain[1].vct).toBe('http://example.com/extending')
    expect(resolvedTypeMetadata?.typeMetadataChain[2].vct).toBe('http://example.com/base')

    // Check vctValues - should have 3 values
    expect(resolvedTypeMetadata?.vctValues).toHaveLength(3)
    expect(resolvedTypeMetadata?.vctValues[0]).toBe('http://example.com/middle')
    expect(resolvedTypeMetadata?.vctValues[1]).toBe('http://example.com/extending')
    expect(resolvedTypeMetadata?.vctValues[2]).toBe('http://example.com/base')
  })

  test('VCT with circular dependency should throw error', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct: 'http://example.com/circular',
      ...claims,
    }

    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    await expect(sdjwt.getVct(encodedSdjwt)).rejects.toThrowError(
      'Circular dependency detected in VCT extends chain: http://example.com/circular'
    )
  })

  test('VCT with a circular dependency back to the credential vct should throw error', async () => {
    const payload: SdJwtVcPayload = { iat, iss, vct: 'http://example.com/cycle-start', ...claims }
    const encodedSdjwt = await sdjwt.issue(payload, disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>)

    await expect(sdjwt.getVct(encodedSdjwt)).rejects.toThrowError(
      'Circular dependency detected in VCT extends chain: http://example.com/cycle-start'
    )
  })

  test('VCT Metadata retrieval fails when the type metadata describes another vct', async () => {
    const payload: SdJwtVcPayload = { iat, iss, vct: 'http://example.com/other-type', ...claims }
    const encodedSdjwt = await sdjwt.issue(payload, disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>)

    await expect(sdjwt.getVct(encodedSdjwt)).rejects.toThrowError(
      "Type metadata fetched for vct 'http://example.com/other-type' describes vct 'urn:eudi:pid:1'"
    )
  })

  test('VCT with extends fails when the extended type metadata describes another vct', async () => {
    const payload: SdJwtVcPayload = { iat, iss, vct: 'http://example.com/extends-other-type', ...claims }
    const encodedSdjwt = await sdjwt.issue(payload, disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>)

    await expect(sdjwt.getVct(encodedSdjwt)).rejects.toThrowError(
      "Type metadata fetched for vct 'http://example.com/other-type' describes vct 'urn:eudi:pid:1'"
    )
  })

  test('VCT with max depth exceeded should throw error', async () => {
    const sdjwtWithShallowDepth = new SDJwtVcInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
      loadTypeMetadataFormat: true,
      timeout: 1000,
      maxVctExtendsDepth: 1, // Only allow 1 level of extends
    })

    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct: 'http://example.com/middle', // This has 2 levels of extends
      ...claims,
    }

    const encodedSdjwt = await sdjwtWithShallowDepth.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    await expect(sdjwtWithShallowDepth.getVct(encodedSdjwt)).rejects.toThrowError(
      'Maximum VCT extends depth of 1 exceeded'
    )
  })

  test('VCT extends chain should work in verify method', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct: 'http://example.com/extending',
      ...claims,
    }

    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    // Should not throw and should resolve the extends chain
    const result = await sdjwt.verify(encodedSdjwt)
    expect(result.payload.vct).toBe('http://example.com/extending')

    // Check that typeMetadata was populated with resolved chain
    expect(result.typeMetadata?.mergedTypeMetadata.claims).toHaveLength(2)
    expect(result.typeMetadata?.typeMetadataChain).toHaveLength(2)
    expect(result.typeMetadata?.vctValues).toHaveLength(2)
  })

  test('VCT with overriding claim metadata', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct: 'http://example.com/overriding',
      ...claims,
    }

    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    const resolvedTypeMetadata = await sdjwt.getVct(encodedSdjwt)

    // Check mergedTypeMetadata - should have 2 claims: overridden firstName and new middleName
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims).toHaveLength(2)

    // First claim should be the overridden firstName with new label and sd property
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims?.[0].path).toEqual(['firstName'])
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims?.[0].display?.[0].label).toBe('Given Name')
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims?.[0].sd).toBe('always')

    // Second claim should be the new middleName
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims?.[1].path).toEqual(['middleName'])
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims?.[1].display?.[0].label).toBe('Middle Name')

    // Check typeMetadataChain - should have 2 documents
    expect(resolvedTypeMetadata?.typeMetadataChain).toHaveLength(2)
    expect(resolvedTypeMetadata?.typeMetadataChain[0].vct).toBe('http://example.com/overriding')
    expect(resolvedTypeMetadata?.typeMetadataChain[1].vct).toBe('http://example.com/base')

    // Check vctValues
    expect(resolvedTypeMetadata?.vctValues).toHaveLength(2)
    expect(resolvedTypeMetadata?.vctValues[0]).toBe('http://example.com/overriding')
    expect(resolvedTypeMetadata?.vctValues[1]).toBe('http://example.com/base')
  })

  test('VCT with valid sd property change (allowed to always)', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct: 'http://example.com/valid-sd-change',
      ...claims,
    }

    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    const resolvedTypeMetadata = await sdjwt.getVct(encodedSdjwt)

    // Check mergedTypeMetadata - should successfully merge - changing from undefined/allowed to always is valid
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims).toHaveLength(1)
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims?.[0].path).toEqual(['firstName'])
    expect(resolvedTypeMetadata?.mergedTypeMetadata.claims?.[0].sd).toBe('always')

    // Check typeMetadataChain
    expect(resolvedTypeMetadata?.typeMetadataChain).toHaveLength(2)
    expect(resolvedTypeMetadata?.vctValues).toHaveLength(2)
  })

  test('VCT with invalid sd property change (always to never) should throw error', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct: 'http://example.com/invalid-sd-change',
      ...claims,
    }

    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    await expect(sdjwt.getVct(encodedSdjwt)).rejects.toThrowError(
      "Cannot change 'sd' property from 'always' to 'never' for claim at path [\"sensitiveData\"]"
    )
  })

  test('VCT extending type without display should inherit base display', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct: 'http://example.com/middle', // middle doesn't define display
      ...claims,
    }

    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    const resolvedTypeMetadata = await sdjwt.getVct(encodedSdjwt)

    // Check mergedTypeMetadata - since middle doesn't define display, it should inherit from extending which has display
    expect(resolvedTypeMetadata?.mergedTypeMetadata.display).toHaveLength(2)
    expect(resolvedTypeMetadata?.mergedTypeMetadata.display?.[0].locale).toBe('en')
    expect(resolvedTypeMetadata?.mergedTypeMetadata.display?.[1].locale).toBe('de')

    // Check typeMetadataChain - should have 3 documents
    expect(resolvedTypeMetadata?.typeMetadataChain).toHaveLength(3)
    expect(resolvedTypeMetadata?.vctValues).toHaveLength(3)
  })

  test('VCT with custom properties are kept', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct: 'http://example.com/custom-properties',
      ...claims,
    }

    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>
    )

    const resolvedTypeMetadata = await sdjwt.getVct(encodedSdjwt)

    expect(resolvedTypeMetadata?.mergedTypeMetadata).toEqual(vctWithCustomProperties)
  })
})
