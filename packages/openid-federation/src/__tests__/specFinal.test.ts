import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { createEntityConfiguration, entityConfigurationClaimsSchema } from '../entityConfiguration'
import { metadataSchema } from '../metadata'
import { trustMarkSchema } from '../trustMark'
import type { SignCallback } from '../utils'
import { validate } from '../utils/validate'

const encode = (value: Record<string, unknown>) => Buffer.from(JSON.stringify(value)).toString('base64url')
const unsignedJwt = (header: Record<string, unknown>, claims: Record<string, unknown>) =>
  `${encode(header)}.${encode(claims)}.c2lnbmF0dXJl`

describe('OpenID Federation 1.0 final', () => {
  const signJwtCallback: SignCallback = () => Promise.resolve(new Uint8Array(8).fill(1))

  it('should read trust marks with trust_mark_type and keep the compact trust mark', () => {
    const trustMarkJwt = unsignedJwt(
      { typ: 'trust-mark+jwt', alg: 'ES256', kid: 'tm' },
      {
        iss: 'https://tm-issuer.example.org',
        sub: 'https://leaf.example.org',
        trust_mark_type: 'https://tm.example.org/certified',
        iat: 1700000000,
      }
    )

    const trustMark = validate({
      schema: trustMarkSchema,
      data: { trust_mark_type: 'https://tm.example.org/certified', trust_mark: trustMarkJwt },
    })

    expect(trustMark.trust_mark_type).toBe('https://tm.example.org/certified')
    expect(trustMark.trust_mark.claims.trust_mark_type).toBe('https://tm.example.org/certified')
    expect(trustMark.trust_mark.jwt).toBe(trustMarkJwt)
  })

  it('should reject a trust mark with the draft id instead of trust_mark_type', () => {
    const trustMarkJwt = unsignedJwt(
      { typ: 'trust-mark+jwt', alg: 'ES256', kid: 'tm' },
      { iss: 'https://tm-issuer.example.org', sub: 'https://leaf.example.org', id: 'https://tm.example.org/a', iat: 1 }
    )

    expect(() =>
      validate({ schema: trustMarkSchema, data: { id: 'https://tm.example.org/a', trust_mark: trustMarkJwt } })
    ).toThrow()
  })

  it('should reject a trust mark without a type', () => {
    const trustMarkJwt = unsignedJwt(
      { typ: 'trust-mark+jwt', alg: 'ES256', kid: 'tm' },
      { iss: 'https://tm-issuer.example.org', sub: 'https://leaf.example.org', iat: 1 }
    )

    expect(() => validate({ schema: trustMarkSchema, data: { trust_mark: trustMarkJwt } })).toThrow()
  })

  it('should reject a trust mark whose type differs from the type in its JWT', () => {
    const trustMarkJwt = unsignedJwt(
      { typ: 'trust-mark+jwt', alg: 'ES256', kid: 'tm' },
      {
        iss: 'https://tm-issuer.example.org',
        sub: 'https://leaf.example.org',
        trust_mark_type: 'https://tm.example.org/b',
        iat: 1,
      }
    )

    expect(() =>
      validate({
        schema: trustMarkSchema,
        data: { trust_mark_type: 'https://tm.example.org/a', trust_mark: trustMarkJwt },
      })
    ).toThrow()
  })

  it('should keep protocol parameters and entity types the schema does not define', () => {
    const metadata = validate({
      schema: metadataSchema,
      data: {
        oauth_authorization_server: {
          issuer: 'https://as.example.org',
          token_endpoint: 'https://as.example.org/token',
        },
        federation_entity: { organization_name: 'Example', display_name: 'Example AS' },
        wallet_provider: { aal_values_supported: ['https://example.org/aal/high'] },
      },
    })

    expect(metadata).toStrictEqual({
      oauth_authorization_server: {
        issuer: 'https://as.example.org',
        token_endpoint: 'https://as.example.org/token',
      },
      federation_entity: { organization_name: 'Example', display_name: 'Example AS' },
      wallet_provider: { aal_values_supported: ['https://example.org/aal/high'] },
    })
  })

  it('should accept credential issuer and verifier metadata without client registration types', () => {
    expect(() =>
      validate({
        schema: metadataSchema,
        data: {
          openid_credential_issuer: { credential_issuer: 'https://issuer.example.org' },
          openid_credential_verifier: { client_name: 'Verifier' },
        },
      })
    ).not.toThrow()
  })

  it('should accept only NumericDate values for iat and exp', async () => {
    const claims = {
      iss: 'https://example.org',
      sub: 'https://example.org',
      jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
    }

    const parsed = validate({
      schema: entityConfigurationClaimsSchema,
      data: { ...claims, iat: 1700000000, exp: 1700086400 },
    })
    expect(parsed.iat).toStrictEqual(new Date(1700000000000))

    for (const iat of ['2023-11-14T22:13:20Z', '1700000000', new Date(1700000000000)]) {
      expect(() =>
        validate({ schema: entityConfigurationClaimsSchema, data: { ...claims, iat, exp: 1700086400 } })
      ).toThrow()
    }

    await expect(
      createEntityConfiguration({
        signJwtCallback,
        claims: { ...claims, iat: new Date(1700000000000), exp: 1700086400 } as never,
        header: { kid: 'a', typ: 'entity-statement+jwt' },
      })
    ).rejects.toThrow()
  })
})
