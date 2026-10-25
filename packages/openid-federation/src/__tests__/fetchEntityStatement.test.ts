import { describe, expect, it } from 'vitest'
import { createEntityConfiguration, fetchEntityConfiguration } from '../entityConfiguration'
import { entityStatementClaimsSchema } from '../entityStatement'
import { createEntityStatement } from '../entityStatement/createEntityStatement'
import { fetchEntityStatement } from '../entityStatement/fetchEntityStatement'
import type { SignCallback, VerifyCallback } from '../utils'
import { mockGet, setupMockServer } from './utils/mockServer'
import { numericDate } from './utils/numericDate'

setupMockServer()

describe('fetch entity statement', () => {
  const signJwtCallback: SignCallback = () => Promise.resolve(new Uint8Array(10).fill(42))
  const verifyJwtCallback: VerifyCallback = () => Promise.resolve(true)

  it('should fetch a basic entity statement', async () => {
    const iss = 'https://example.org'
    const sub = 'https://one.example.org'

    const issEntityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        jwks: {
          keys: [{ kid: 'a', kty: 'EC' }],
        },
        sub: iss,
        iss,
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: `${iss}/fetch`,
          },
        },
        iat: 1,
        exp: 1,
      },
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
    })

    const entityStatementClaims = {
      exp: numericDate(),
      iat: numericDate(),
      iss,
      sub,
      jwks: { keys: [{ kty: 'EC', kid: 'b' }] },
    }

    const entityStatementJwt = await createEntityStatement({
      jwk: { kty: 'EC', kid: 'a' },
      claims: entityStatementClaims,
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
      signJwtCallback,
    })

    const mockedResponses = [
      mockGet('https://example.org/.well-known/openid-federation', { body: issEntityConfigurationJwt }),
      mockGet('https://example.org/fetch', { body: entityStatementJwt, query: { sub } }),
    ]

    const fetchedEntityConfiguration = await fetchEntityConfiguration({
      entityId: iss,
      verifyJwtCallback,
    })

    const fetchedEntityStatement = await fetchEntityStatement({
      verifyJwtCallback,
      iss,
      sub,
      issEntityConfiguration: fetchedEntityConfiguration,
    })

    expect(fetchedEntityStatement).toStrictEqual(entityStatementClaimsSchema.parse(entityStatementClaims))

    for (const mockedResponse of mockedResponses) mockedResponse.done()
  })

  it('should fetch a basic entity statement without providing iss entity configuration', async () => {
    const iss = 'https://example.org'
    const sub = 'https://one.example.org'

    const issEntityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        jwks: {
          keys: [{ kid: 'a', kty: 'EC' }],
        },
        sub: iss,
        iss,
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: `${iss}/fetch`,
          },
        },
        iat: 1,
        exp: 1,
      },
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
    })

    const entityStatementClaims = {
      exp: numericDate(),
      iat: numericDate(),
      iss,
      sub,
      jwks: { keys: [{ kty: 'EC', kid: 'b' }] },
    }

    const entityStatementJwt = await createEntityStatement({
      jwk: { kty: 'EC', kid: 'a' },
      claims: entityStatementClaims,
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
      signJwtCallback,
    })

    const mockedResponses = [
      mockGet('https://example.org/.well-known/openid-federation', { body: issEntityConfigurationJwt }),
      mockGet('https://example.org/fetch', { body: entityStatementJwt, query: { sub } }),
    ]

    const fetchedEntityStatement = await fetchEntityStatement({
      verifyJwtCallback,
      iss,
      sub,
    })

    expect(fetchedEntityStatement).toStrictEqual(entityStatementClaimsSchema.parse(entityStatementClaims))

    for (const mockedResponse of mockedResponses) mockedResponse.done()
  })

  it('should fetch a basic entity statement with providing the endpoint manually', async () => {
    const iss = 'https://example.org'
    const sub = 'https://one.example.org'

    const issEntityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        jwks: {
          keys: [{ kid: 'a', kty: 'EC' }],
        },
        sub: iss,
        iss,
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: `${iss}/fetch`,
          },
        },
        iat: 1,
        exp: 1,
      },
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
    })

    const entityStatementClaims = {
      exp: numericDate(),
      iat: numericDate(),
      iss,
      sub,
      jwks: { keys: [{ kty: 'EC', kid: 'b' }] },
    }

    const entityStatementJwt = await createEntityStatement({
      jwk: { kty: 'EC', kid: 'a' },
      claims: entityStatementClaims,
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
      signJwtCallback,
    })

    const mockedResponses = [
      mockGet('https://example.org/.well-known/openid-federation', { body: issEntityConfigurationJwt }),
      mockGet('https://example.org/fetch', { body: entityStatementJwt, query: { sub } }),
    ]

    const fetchedEntityStatement = await fetchEntityStatement({
      verifyJwtCallback,
      iss,
      sub,
      endpoint: `${iss}/fetch`,
    })

    expect(fetchedEntityStatement).toStrictEqual(entityStatementClaimsSchema.parse(entityStatementClaims))

    for (const mockedResponse of mockedResponses) mockedResponse.done()
  })

  it('should not fetch an entity statement without a fetch endpoint', async () => {
    const iss = 'https://example.org'
    const sub = 'https://one.example.org'

    const issEntityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        jwks: {
          keys: [{ kid: 'a', kty: 'EC' }],
        },
        sub: iss,
        iss,
        iat: 1,
        exp: 1,
      },
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
    })

    const mockedResponse = mockGet('https://example.org/.well-known/openid-federation', {
      body: issEntityConfigurationJwt,
    })

    await expect(
      fetchEntityStatement({
        verifyJwtCallback,
        iss,
        sub,
      })
    ).rejects.toThrow()

    mockedResponse.done()
  })

  it('should not fetch an entity statement without anything hosted on the fetch endpoint', async () => {
    const iss = 'https://example.org'
    const sub = 'https://one.example.org'

    const issEntityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        jwks: {
          keys: [{ kid: 'a', kty: 'EC' }],
        },
        sub: iss,
        iss,
        iat: 1,
        exp: 1,
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: `${iss}/fetch`,
          },
        },
      },
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
    })

    const mockedResponses = [
      mockGet('https://example.org/.well-known/openid-federation', { body: issEntityConfigurationJwt }),
      mockGet('https://example.org/fetch', { status: 404, query: { sub } }),
    ]

    await expect(
      fetchEntityStatement({
        verifyJwtCallback,
        iss,
        sub,
      })
    ).rejects.toThrow()

    for (const mockedResponse of mockedResponses) mockedResponse.done()
  })

  it('should not fetch an entity statement with an invalid content-type', async () => {
    const iss = 'https://example.org'
    const sub = 'https://one.example.org'

    const issEntityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        jwks: {
          keys: [{ kid: 'a', kty: 'EC' }],
        },
        sub: iss,
        iss,
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: `${iss}/fetch`,
          },
        },
        iat: 1,
        exp: 1,
      },
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
    })

    const entityStatementClaims = {
      exp: numericDate(),
      iat: numericDate(),
      iss,
      sub,
      jwks: { keys: [{ kty: 'EC', kid: 'b' }] },
    }

    const entityStatementJwt = await createEntityStatement({
      jwk: { kty: 'EC', kid: 'a' },
      claims: entityStatementClaims,
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
      signJwtCallback,
    })

    const mockedResponses = [
      mockGet('https://example.org/.well-known/openid-federation', { body: issEntityConfigurationJwt }),
      mockGet('https://example.org/fetch', {
        body: entityStatementJwt,
        query: { sub },
        contentType: 'invalid-content',
      }),
    ]

    await expect(
      fetchEntityStatement({
        verifyJwtCallback,
        iss,
        sub,
      })
    ).rejects.toThrow()

    for (const mockedResponse of mockedResponses) mockedResponse.done()
  })
})
