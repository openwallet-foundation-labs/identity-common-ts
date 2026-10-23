import { describe, expect, it } from 'vitest'
import {
  createEntityConfiguration,
  type EntityConfigurationClaimsOptions,
  entityConfigurationClaimsSchema,
  fetchEntityConfiguration,
} from '../entityConfiguration'
import type { SignCallback, VerifyCallback } from '../utils'
import { mockGet, setupMockServer } from './utils/mockServer'
import { numericDate } from './utils/numericDate'

setupMockServer()

describe('fetch entity configuration', () => {
  const verifyJwtCallback: VerifyCallback = () => Promise.resolve(true)

  const signJwtCallback: SignCallback = () => Promise.resolve(new Uint8Array(10).fill(42))

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

    expect(fetchedEntityConfiguration).toStrictEqual(entityConfigurationClaimsSchema.parse(claims))

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

    expect(fetchedEntityConfiguration).toStrictEqual(entityConfigurationClaimsSchema.parse(claims))

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
