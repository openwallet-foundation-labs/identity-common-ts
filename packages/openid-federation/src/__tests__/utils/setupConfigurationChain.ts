import {
  createEntityConfiguration,
  type EntityConfigurationClaimsOptions,
  type EntityConfigurationHeaderOptions,
} from '../../entityConfiguration'
import {
  createEntityStatement,
  type EntityStatementClaimsOptions,
  entityStatementClaimsSchema,
} from '../../entityStatement'
import type { JsonWebKeySetOptions } from '../../jsonWeb'
import type { SignCallback } from '../../utils'
import { type MockedResponse, mockGet, server } from './mockServer'
import { numericDate } from './numericDate'

type SubordinateOptions = {
  entityId: string
  claims: Partial<EntityStatementClaimsOptions>
}

type ChainConfigurationOptions = {
  entityId: string
  authorityHints?: Array<string>
  subordinates?: Array<string | SubordinateOptions>
  jwks?: JsonWebKeySetOptions
  kid?: string
  includeSourceEndpoint?: boolean

  claims?: Partial<EntityConfigurationClaimsOptions>
}

export const setupConfigurationChain = async <MockEndpoints extends boolean>(
  chainOptions: Array<ChainConfigurationOptions>,
  {
    signJwtCallback,
    mockEndpoints = false as MockEndpoints,
  }: {
    signJwtCallback: SignCallback
    /**
     * @default false
     */
    mockEndpoints?: MockEndpoints
  }
) => {
  if (mockEndpoints) {
    server.resetHandlers()
  }

  const chainData: Array<{
    claims: EntityConfigurationClaimsOptions
    jwt: string
    entityId: string
    subordinateStatements?: Array<{ entityId: string; jwt: string; claims: EntityStatementClaimsOptions }>
  }> = []
  const mockedResponses: Array<MockedResponse> = []
  for (const {
    entityId,
    authorityHints,
    jwks,
    kid,
    subordinates,
    includeSourceEndpoint = true,
    claims: givenClaims = {},
  } of chainOptions) {
    const claims: EntityConfigurationClaimsOptions = {
      iss: entityId,
      sub: entityId,
      exp: numericDate(1000 * 60 * 60 * 24 * 30), // 30 days
      iat: numericDate(),
      jwks: jwks ?? { keys: [{ kid: 'a', kty: 'EC' }] },
      authority_hints: authorityHints,
      ...givenClaims,
      metadata: {
        federation_entity: {
          federation_fetch_endpoint: `${entityId}/fetch`,
        },
        ...(givenClaims.metadata ?? {}),
      },
    }

    // fix so `undefined` is not in the expected claims
    if (!authorityHints) delete claims.authority_hints
    if (!includeSourceEndpoint) delete claims.source_endpoint

    const header: EntityConfigurationHeaderOptions = {
      kid: kid ?? 'a',
      typ: 'entity-statement+jwt',
    }

    const jwt = await createEntityConfiguration({
      claims,
      header,
      signJwtCallback,
    })

    if (mockEndpoints) {
      mockedResponses.push(mockGet(`${entityId}/.well-known/openid-federation`, { body: jwt }))
    }

    const subordinateStatements: Array<{ entityId: string; jwt: string; claims: EntityStatementClaimsOptions }> = []
    for (const sub of subordinates ?? []) {
      const givenClaims = typeof sub === 'string' ? { sub } : { sub: sub.entityId, ...sub.claims }

      // A subordinate statement lists the subject's federation keys
      const subordinateClaims = {
        jwks: chainOptions.find((options) => options.entityId === givenClaims.sub)?.jwks ?? {
          keys: [{ kid: 'a', kty: 'EC' }],
        },
        iss: entityId,
        exp: numericDate(1000 * 60 * 60 * 24 * 30), // 30 days
        iat: numericDate(),
        ...givenClaims,
      }

      const entityStatementJwt = await createEntityStatement({
        signJwtCallback,
        jwk: claims.jwks.keys[0],
        claims: subordinateClaims,
      })

      if (mockEndpoints && claims.metadata?.federation_entity?.federation_fetch_endpoint) {
        mockedResponses.push(
          mockGet(claims.metadata.federation_entity.federation_fetch_endpoint, {
            body: entityStatementJwt,
            query: { sub: subordinateClaims.sub },
          })
        )
      }

      subordinateStatements.push({
        entityId: subordinateClaims.sub,
        jwt: entityStatementJwt,
        claims: subordinateClaims,
      })
    }

    chainData.push({
      claims,
      jwt,
      entityId,
      subordinateStatements,
    })
  }

  return {
    chainData,
    mockedResponses: (mockEndpoints ? mockedResponses : undefined) as MockEndpoints extends true
      ? typeof mockedResponses
      : never,
  } as const
}

/**
 *
 * The subordinate statements of a chain set up with {@link setupConfigurationChain}, leaf side first, as the
 * resolver passes them to the metadata policy functions.
 *
 */
export const subordinateStatements = (
  chainData: Array<{ subordinateStatements?: Array<{ claims: EntityStatementClaimsOptions }> }>
) =>
  chainData
    .slice(1)
    .flatMap(({ subordinateStatements = [] }) =>
      subordinateStatements.map(({ claims }) => entityStatementClaimsSchema.parse(claims))
    )
