import { parseWithSchema } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { zCredentialRequestJwtProofTypeHeader } from '../../../../formats/proof-type/jwt/z-jwt-proof-type'

const jwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
}

describe('JWT proof type header', () => {
  // OpenID4VCI 1.0 Appendix F.1: jwk and kid are mutually exclusive, and trust_chain requires kid
  test('rejects jwk together with kid as not_allowed at jwk', () => {
    const result = parseWithSchema(zCredentialRequestJwtProofTypeHeader, {
      alg: 'ES256',
      typ: 'openid4vci-proof+jwt',
      kid: 'key-1',
      jwk,
    })

    expect(result).toMatchObject({
      success: false,
      issues: [
        { code: 'not_allowed', path: ['jwk'], message: `Both 'jwk' and 'kid' are defined. Only one is allowed` },
      ],
    })
  })

  test('rejects trust_chain without kid as missing_value at kid', () => {
    const result = parseWithSchema(zCredentialRequestJwtProofTypeHeader, {
      alg: 'ES256',
      typ: 'openid4vci-proof+jwt',
      jwk,
      trust_chain: ['ey.ey.S'],
    })

    expect(result).toMatchObject({
      success: false,
      issues: [{ code: 'missing_value', path: ['kid'], context: { expected: 'string' } }],
    })
  })
})
