import { describe, expect, it, vi } from 'vitest'
import {
  createEntityConfiguration,
  type EntityConfigurationClaimsOptions,
  fetchEntityConfiguration,
  zEntityConfigurationClaims,
} from '../entityConfiguration'
import type { SignCallback, VerifyCallback } from '../utils'
import { mockGet, setupMockServer } from './utils/mockServer'
import { numericDate } from './utils/numericDate'

setupMockServer()

describe('fetch entity configuration', () => {
  const verifyJwtCallback: VerifyCallback = () => Promise.resolve(true)

  const signJwtCallback: SignCallback = () => Promise.resolve(new Uint8Array(10).fill(42))

  // OpenID Federation 1.0 Section 1.2 and 5.1.1: Entity Identifiers and federation endpoints are https URLs. They are
  // fetched before the trust chain is trusted, so another scheme would let any entity make the resolver request, for
  // example, an internal http endpoint.
  it('should not fetch the entity configuration of an entity id that is not an https URL', async () => {
    const fetchCallback = vi.fn()

    await expect(
      fetchEntityConfiguration({ entityId: 'http://10.0.0.5:8080', verifyJwtCallback, fetchCallback })
    ).rejects.toThrow('is not an https URL')
    expect(fetchCallback).not.toHaveBeenCalled()
  })

  it('should reject authority hints and federation endpoints that are not https URLs', () => {
    const claims = {
      iss: 'https://example.org',
      sub: 'https://example.org',
      iat: numericDate(),
      exp: numericDate(),
      jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
    }

    expect(zEntityConfigurationClaims.safeParse({ ...claims, authority_hints: ['http://10.0.0.5'] }).success).toBe(
      false
    )
    expect(
      zEntityConfigurationClaims.safeParse({
        ...claims,
        metadata: { federation_entity: { federation_fetch_endpoint: 'http://10.0.0.5/fetch' } },
      }).success
    ).toBe(false)
  })

  it('should fetch a simple entity configuration', async () => {
    const entityId = 'https://example.org'

    const claims = {
      iss: entityId,
      sub: entityId,
      iat: numericDate(),
      exp: numericDate(),
      jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
    }

    const entityConfiguration = await createEntityConfiguration({
      header: { kid: 'a', typ: 'entity-statement+jwt' },
      claims,
      signJwtCallback,
    })

    const mockedResponse = mockGet(`${entityId}/.well-known/openid-federation`, { body: entityConfiguration })

    const fetchedEntityConfiguration = await fetchEntityConfiguration({
      entityId,
      verifyJwtCallback,
    })

    expect(fetchedEntityConfiguration).toStrictEqual(zEntityConfigurationClaims.parse(claims))

    mockedResponse.done()
  })

  it('should fetch an entity configuration with metadata and unknown properties', async () => {
    const entityId = 'https://example.org'

    const claims = {
      iss: entityId,
      sub: entityId,
      iat: numericDate(),
      exp: numericDate(),
      metadata: {
        openid_relying_party: {
          client_name: 'bakfiets',
          client_registration_types: ['automatic'],
        },
      },
      jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
    } satisfies EntityConfigurationClaimsOptions

    const entityConfiguration = await createEntityConfiguration({
      header: { kid: 'a', typ: 'entity-statement+jwt' },
      claims,
      signJwtCallback,
    })

    const mockedResponse = mockGet(`${entityId}/.well-known/openid-federation`, { body: entityConfiguration })

    const fetchedEntityConfiguration = await fetchEntityConfiguration({
      entityId,
      verifyJwtCallback,
    })

    expect(fetchedEntityConfiguration).toStrictEqual(zEntityConfigurationClaims.parse(claims))

    mockedResponse.done()
  })

  it('should not fetch an entity configuration when the content-type is invalid', async () => {
    const entityId = 'https://exampletwo.org'

    const claims = {
      iss: entityId,
      sub: entityId,
      iat: numericDate(),
      exp: numericDate(),
      jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
    }

    const entityConfiguration = await createEntityConfiguration({
      header: { kid: 'a', typ: 'entity-statement+jwt' },
      claims,
      signJwtCallback,
    })

    const mockedResponse = mockGet(`${entityId}/.well-known/openid-federation`, {
      body: entityConfiguration,
      contentType: 'invalid-type',
    })

    await expect(fetchEntityConfiguration({ entityId, verifyJwtCallback })).rejects.toThrow()

    mockedResponse.done()
  })

  it('should not fetch an entity configuration when there is no entity configuration', async () => {
    const entityId = 'https://examplethree.org'

    const mockedResponse = mockGet(`${entityId}/.well-known/openid-federation`, { status: 404 })

    await expect(fetchEntityConfiguration({ entityId, verifyJwtCallback })).rejects.toThrow()

    mockedResponse.done()
  })
})
