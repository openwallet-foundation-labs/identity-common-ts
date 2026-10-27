import { describe, expect, it } from 'vitest'
import {
  createEntityConfiguration,
  entityConfigurationClaimsSchema,
  fetchEntityConfiguration,
} from '../entityConfiguration'
import { createEntityStatement, entityStatementClaimsSchema, fetchEntityStatement } from '../entityStatement'
import type { SignCallback, VerifyCallback } from '../utils'
import { mockGet, setupMockServer } from './utils/mockServer'
import { numericDate } from './utils/numericDate'

setupMockServer()

const { subtle } = globalThis.crypto

describe('End To End', async () => {
  const key = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const exportedKey = await subtle.exportKey('jwk', key.publicKey)
  const publicKeyJwk = {
    kid: 'some-id',
    kty: 'EC',
    key_ops: exportedKey.key_ops,
    x: exportedKey.x,
    y: exportedKey.y,
    crv: exportedKey.crv,
  }

  const signJwtCallback: SignCallback = async ({ toBeSigned }) =>
    new Uint8Array(await subtle.sign({ hash: 'SHA-256', name: 'ECDSA' }, key.privateKey, new Uint8Array(toBeSigned)))

  const verifyJwtCallback: VerifyCallback = async ({ signature, data, jwk }) => {
    const publicKey = await subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])

    return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, new Uint8Array(signature), new Uint8Array(data))
  }

  it('should fetch an entity configuration', async () => {
    const iss = 'https://example.org'

    const claims = {
      iss,
      sub: iss,
      exp: numericDate(),
      iat: numericDate(),
      jwks: {
        keys: [publicKeyJwk],
      },
    }

    const entityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims,
      header: {
        kid: 'some-id',
        typ: 'entity-statement+jwt',
      },
    })

    const mockedResponse = mockGet(`${iss}/.well-known/openid-federation`, { body: entityConfigurationJwt })

    const fetchedEntityConfigurationClaims = await fetchEntityConfiguration({
      entityId: iss,
      verifyJwtCallback,
    })

    expect(fetchedEntityConfigurationClaims).toStrictEqual(entityConfigurationClaimsSchema.parse(claims))

    mockedResponse.done()
  })

  it('should fetch an entity statement', async () => {
    const iss = 'https://example.org'
    const sub = 'https://sub.example.org'

    const entityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        iss,
        sub: iss,
        exp: numericDate(),
        iat: numericDate(),
        jwks: {
          keys: [publicKeyJwk],
        },
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: `${iss}/fetch`,
          },
        },
      },
      header: {
        kid: 'some-id',
        typ: 'entity-statement+jwt',
      },
    })

    const entityStamentClaims = {
      iss,
      sub,
      exp: numericDate(),
      iat: numericDate(),
      jwks: {
        keys: [],
      },
      authority_hints: [iss],
      metadata: {
        federation_entity: {
          organization_name: 'my org!',
        },
      },
    }

    const entityStatementJwt = await createEntityStatement({
      signJwtCallback,
      claims: entityStamentClaims,
      header: {
        kid: 'some-id',
        typ: 'entity-statement+jwt',
      },
      jwk: publicKeyJwk,
    })

    const mockedResponses = [
      mockGet(`${iss}/.well-known/openid-federation`, { body: entityConfigurationJwt }),
      mockGet(`${iss}/fetch`, { body: entityStatementJwt, query: { sub } }),
    ]

    const fetchedEntityConfigurationClaims = await fetchEntityConfiguration({
      entityId: iss,
      verifyJwtCallback,
    })

    const fetchedEntityStatementClaims = await fetchEntityStatement({
      iss,
      sub,
      issEntityConfiguration: fetchedEntityConfigurationClaims,
      verifyJwtCallback,
    })

    expect(fetchedEntityStatementClaims).toStrictEqual(entityStatementClaimsSchema.parse(entityStamentClaims))

    for (const mockedResponse of mockedResponses) mockedResponse.done()
  })
})
