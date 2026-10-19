import { describe, expect, it } from 'vitest'
import { createEntityConfiguration } from '../entityConfiguration'
import type { SignCallback } from '../utils'

describe('create entity configuration', () => {
  const signJwtCallback: SignCallback = () => Promise.resolve(new Uint8Array(42).fill(8))

  it('should create a basic entity configuration', async () => {
    const entityConfiguration = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        exp: 1,
        iat: 1,
        iss: 'https://example.org',
        sub: 'https://example.org',
        jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
      },
      header: { kid: 'a', typ: 'entity-statement+jwt' },
    })

    expect(entityConfiguration).toBe(
      'eyJraWQiOiJhIiwidHlwIjoiZW50aXR5LXN0YXRlbWVudCtqd3QifQ.eyJleHAiOjEsImlhdCI6MSwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLm9yZyIsInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5vcmciLCJqd2tzIjp7ImtleXMiOlt7ImtpZCI6ImEiLCJrdHkiOiJFQyJ9XX19.CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI'
    )
  })

  it('should create a more complex entity configuration', async () => {
    const entityConfiguration = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        exp: 1,
        iat: 1,
        iss: 'https://example.org',
        sub: 'https://example.org',
        jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
        authority_hints: ['https://foo.com'],
      },
      header: { kid: 'a', typ: 'entity-statement+jwt' },
    })

    expect(entityConfiguration).toBe(
      'eyJraWQiOiJhIiwidHlwIjoiZW50aXR5LXN0YXRlbWVudCtqd3QifQ.eyJleHAiOjEsImlhdCI6MSwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLm9yZyIsInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5vcmciLCJqd2tzIjp7ImtleXMiOlt7ImtpZCI6ImEiLCJrdHkiOiJFQyJ9XX0sImF1dGhvcml0eV9oaW50cyI6WyJodHRwczovL2Zvby5jb20iXX0.CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI'
    )
  })

  it('should not create a entity configuration when iss and sub are not equal', async () => {
    await expect(
      createEntityConfiguration({
        signJwtCallback,
        claims: {
          exp: 1,
          iat: 1,
          iss: 'https://some-other.url',
          sub: 'https://example.org',
          jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
        },
        header: { kid: 'a', typ: 'entity-statement+jwt' },
      })
    ).rejects.toThrow()
  })

  it('should not create a entity configuration when kid is not found in jwks.keys', async () => {
    await expect(
      createEntityConfiguration({
        signJwtCallback,
        claims: {
          exp: 1,
          iat: 1,
          iss: 'https://example.org',
          sub: 'https://example.org',
          jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
        },
        header: { kid: 'invalid_id', typ: 'entity-statement+jwt' },
      })
    ).rejects.toThrow()
  })

  it("should not create a entity configuration when typ is not 'entity-statement+jwt'", async () => {
    await expect(
      createEntityConfiguration({
        signJwtCallback,
        claims: {
          exp: 1,
          iat: 1,
          iss: 'https://example.org',
          sub: 'https://example.org',
          jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
        },
        // @ts-expect-error
        header: { kid: 'a', typ: 'invalid_typ' },
      })
    ).rejects.toThrow()
  })

  it('should not create a entity configuration when jwks.keys include keys with the same kid', async () => {
    await expect(
      createEntityConfiguration({
        signJwtCallback,
        claims: {
          exp: 1,
          iat: 1,
          iss: 'https://example.org',
          sub: 'https://example.org',
          jwks: {
            keys: [
              { kid: 'a', kty: 'EC' },
              { kid: 'a', kty: 'EC' },
            ],
          },
        },
        header: { kid: 'a', typ: 'entity-statement+jwt' },
      })
    ).rejects.toThrow()
  })
})
