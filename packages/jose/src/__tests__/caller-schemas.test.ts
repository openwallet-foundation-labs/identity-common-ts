import { base64url, dateToSeconds, stringToBytes } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import z from 'zod'
import type { VerifyJwsCallback, VerifyJwsCallbackContext } from '../callbacks'
import {
  JoseAlgorithmNotAllowedError,
  JoseNotSupportedError,
  JoseParseError,
  JoseSignerError,
  JoseValidationError,
} from '../error'
import { jwsHeaderFromSigner } from '../jws/signer'
import { type DecodeJwtResult, decodeJwt, decodeJwtHeader } from '../jwt/decode-jwt'
import { signJwt } from '../jwt/sign-jwt'
import { verifyJwt } from '../jwt/verify-jwt'
import { zJwtPayload } from '../jwt/z-jwt'
import { claimIssue, createEs256Context, unsignedCompactJws } from './context'

const now = new Date('2026-09-15T12:00:00Z')
const hourAgo = dateToSeconds(now) - 3600
const hourAhead = dateToSeconds(now) + 3600
const ecJwk = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }
const verifiedWith =
  (signerJwk: Record<string, unknown>): VerifyJwsCallback =>
  () => ({ verified: true, signerJwk: { kty: 'EC', ...signerJwk } })

/**
 * Schemas in zod's default mode drop the members they do not declare. A schema describing a profile's
 * own parameters or claims must not be able to take the registered ones out of verification that way:
 * every check is made on the header and claims as validated against the registered schemas.
 */
const zTypOnlyHeader = z.object({ typ: z.string() })
const zIssOnlyPayload = z.object({ iss: z.string() })

describe('verifyJwt with a header schema that drops the registered parameters', () => {
  it('rejects a symmetric algorithm', async () => {
    const jwt = unsignedCompactJws({ alg: 'HS256', typ: 'example+jwt' }, { iss: 'https://issuer.example' })

    await expect(
      verifyJwt({ jwt, headerSchema: zTypOnlyHeader, verifyJwsCallback: verifiedWith(ecJwk), now })
    ).rejects.toThrow(
      new JoseAlgorithmNotAllowedError(
        `Error during verification of the JWT. The JWS uses the symmetric algorithm 'HS256'. Set 'allowSymmetricAlgorithms' if a MAC is expected here.`
      )
    )
  })

  it('rejects a key that cannot be used with the algorithm of the token', async () => {
    const jwt = unsignedCompactJws({ alg: 'ES256', typ: 'example+jwt' }, { iss: 'https://issuer.example' })

    await expect(
      verifyJwt({
        jwt,
        headerSchema: zTypOnlyHeader,
        verifyJwsCallback: verifiedWith({ kty: 'RSA', n: 'n', e: 'AQAB' }),
        now,
      })
    ).rejects.toThrow(`Algorithm 'ES256' requires a key with kty 'EC', but the key has kty 'RSA'.`)
  })

  it('establishes the signer from the jwk header parameter', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()
    const signer = { method: 'jwk', alg: 'ES256', publicJwk } as const
    const { jwt } = await signJwt({
      header: { ...jwsHeaderFromSigner(signer), typ: 'example+jwt' },
      payload: { iss: 'https://issuer.example' },
      signer,
      signJwsCallback: signJws,
    })

    const verified = await verifyJwt({ jwt, headerSchema: zTypOnlyHeader, verifyJwsCallback: verifyJws, now })

    expect(verified.signer).toEqual({ method: 'jwk', alg: 'ES256', publicJwk })
  })

  it('gives the verification callback the header as it was signed', async () => {
    const contexts: VerifyJwsCallbackContext[] = []
    const jwt = unsignedCompactJws(
      { alg: 'ES256', typ: 'example+jwt', kid: 'key-1' },
      { iss: 'https://issuer.example' }
    )

    await verifyJwt({
      jwt,
      headerSchema: zTypOnlyHeader,
      verifyJwsCallback: (_signer, context) => {
        contexts.push(context)
        return { verified: true, signerJwk: ecJwk }
      },
      now,
    })

    expect(contexts[0].protectedHeader).toEqual({ alg: 'ES256', typ: 'example+jwt', kid: 'key-1' })
  })

  it('returns the header as the schema returned it', async () => {
    const jwt = unsignedCompactJws({ alg: 'ES256', typ: 'example+jwt' }, { iss: 'https://issuer.example' })

    const verified = await verifyJwt({ jwt, headerSchema: zTypOnlyHeader, verifyJwsCallback: verifiedWith(ecJwk), now })

    expect(verified.header).toEqual({ typ: 'example+jwt' })
  })
})

describe('verifyJwt with a payload schema that drops the registered claims', () => {
  const verify = (payload: Record<string, unknown>, options: Partial<Parameters<typeof verifyJwt>[0]> = {}) =>
    verifyJwt({
      jwt: unsignedCompactJws({ alg: 'ES256' }, payload),
      payloadSchema: zIssOnlyPayload,
      verifyJwsCallback: verifiedWith(ecJwk),
      now,
      ...options,
    })

  it('rejects a token that expired an hour ago', async () => {
    await expect(verify({ iss: 'https://issuer.example', exp: hourAgo })).rejects.toThrow(claimIssue('exp', 'expired'))
  })

  it('rejects a token that is not valid for another hour', async () => {
    await expect(verify({ iss: 'https://issuer.example', nbf: hourAhead })).rejects.toThrow(
      claimIssue('nbf', 'not_yet_valid')
    )
  })

  it('binds a did kid to the iss that the schema drops', async () => {
    const zNoIssPayload = z.object({ vct: z.string() })
    const jwt = unsignedCompactJws(
      { alg: 'ES256', kid: 'did:web:other.example#key-1' },
      { iss: 'did:web:issuer.example', vct: 'https://example.com/card' }
    )

    await expect(
      verifyJwt({ jwt, payloadSchema: zNoIssPayload, verifyJwsCallback: verifiedWith(ecJwk), now })
    ).rejects.toThrow(JoseSignerError)
  })

  it('gives the verification callback the claims as they were signed', async () => {
    const contexts: VerifyJwsCallbackContext[] = []

    await verify(
      { iss: 'https://issuer.example', exp: hourAhead },
      {
        verifyJwsCallback: (_signer, context) => {
          contexts.push(context)
          return { verified: true, signerJwk: ecJwk }
        },
      }
    )

    expect(contexts[0].jwtPayload).toEqual({ iss: 'https://issuer.example', exp: hourAhead })
  })

  it('returns the payload as the schema returned it', async () => {
    const verified = await verify({ iss: 'https://issuer.example', exp: hourAhead })

    expect(verified.payload).toEqual({ iss: 'https://issuer.example' })
  })
})

describe('verifyJwt with a payload schema that fills in registered claims', () => {
  const zIssuedNowPayload = z.object({ ...zJwtPayload.shape, iat: z.number().default(dateToSeconds(now)) }).loose()
  const jwt = unsignedCompactJws({ alg: 'ES256' }, { iss: 'https://issuer.example' })

  it('rejects a token without iat when a maximum age is required', async () => {
    await expect(
      verifyJwt({
        jwt,
        payloadSchema: zIssuedNowPayload,
        verifyJwsCallback: verifiedWith(ecJwk),
        now,
        maxAgeSeconds: 60,
      })
    ).rejects.toThrow(claimIssue('iat', 'claim_missing'))
  })

  it('rejects a token without a required iat', async () => {
    await expect(
      verifyJwt({
        jwt,
        payloadSchema: zIssuedNowPayload,
        verifyJwsCallback: verifiedWith(ecJwk),
        now,
        requiredClaims: ['iat'],
      })
    ).rejects.toThrow(claimIssue('iat', 'claim_missing'))
  })
})

describe('decodeJwt with schemas that drop the registered parameters and claims', () => {
  // With `b64` false the payload part is the payload itself — here, text that also happens to be
  // base64url encoded JSON, which is what a JWT would hold there
  const unencodedJwt = () => {
    const encode = (value: unknown) => base64url.encode(stringToBytes(JSON.stringify(value)))
    return `${encode({ alg: 'ES256', b64: false, crit: ['b64'] })}.${encode({ iss: 'https://issuer.example' })}.c2ln`
  }

  it('rejects an unencoded payload when the header schema drops b64', () => {
    const zCritOnlyHeader = z.object({ alg: z.string(), crit: z.array(z.string()) })

    expect(() =>
      decodeJwt({ jwt: unencodedJwt(), headerSchema: zCritOnlyHeader, understoodCriticalParameters: ['b64'] })
    ).toThrow(JoseNotSupportedError)
  })

  it('returns the header and payload as validated against the registered schemas', () => {
    const jwt = unsignedCompactJws(
      { alg: 'ES256', typ: 'example+jwt' },
      { iss: 'https://issuer.example', exp: hourAhead }
    )

    const decoded = decodeJwt({ jwt, headerSchema: zTypOnlyHeader, payloadSchema: zIssOnlyPayload })

    expect({ registeredHeader: decoded.registeredHeader, registeredPayload: decoded.registeredPayload }).toEqual({
      registeredHeader: { alg: 'ES256', typ: 'example+jwt' },
      registeredPayload: { iss: 'https://issuer.example', exp: hourAhead },
    })
  })
})

/**
 * A decoded JWT can be passed to `verifyJwt` instead of a compact one. One that was put together
 * without `decodeJwt` does not come with the registered header and claims, so those are validated.
 */
describe('verifyJwt with a decoded JWT that was not returned by decodeJwt', () => {
  const decoded = (header: Record<string, unknown>, payload: Record<string, unknown>) => {
    const compact = unsignedCompactJws(header, payload)
    const [encodedHeader, encodedPayload, signature] = compact.split('.')
    return {
      header,
      payload,
      payloadBytes: stringToBytes(JSON.stringify(payload)),
      signature,
      signingInput: `${encodedHeader}.${encodedPayload}`,
      compact,
    }
  }

  it("rejects a header whose alg is 'none'", async () => {
    const jwt = decoded({ alg: 'none' }, { iss: 'https://issuer.example' }) as unknown as DecodeJwtResult

    await expect(verifyJwt({ jwt, verifyJwsCallback: verifiedWith(ecJwk), now })).rejects.toThrow(
      expect.objectContaining({
        name: JoseValidationError.name,
        message: expect.stringContaining(`value may not be 'none'`),
      })
    )
  })

  it('rejects claims that are not valid registered claims', async () => {
    const jwt = decoded({ alg: 'ES256' }, { exp: 'tomorrow' }) as unknown as DecodeJwtResult

    await expect(verifyJwt({ jwt, verifyJwsCallback: verifiedWith(ecJwk), now })).rejects.toThrow(JoseValidationError)
  })

  it('does not apply the schemas passed next to a decoded JWT', async () => {
    const jwt = decodeJwt({
      jwt: unsignedCompactJws({ alg: 'ES256', typ: 'example+jwt' }, { iss: 'https://issuer.example' }),
    })

    const verified = await verifyJwt({
      jwt,
      headerSchema: z.object({ typ: z.literal('other+jwt') }),
      payloadSchema: z.object({ vct: z.string() }),
      verifyJwsCallback: verifiedWith(ecJwk),
      now,
    })

    expect(verified.payload).toEqual({ iss: 'https://issuer.example' })
  })

  it("rejects a registered header whose alg is 'none'", async () => {
    const jwt: DecodeJwtResult = {
      ...decoded({ alg: 'ES256' }, { iss: 'https://issuer.example' }),
      header: { alg: 'ES256' },
      registeredHeader: { alg: 'none' },
      registeredPayload: { iss: 'https://issuer.example' },
    }

    await expect(verifyJwt({ jwt, verifyJwsCallback: verifiedWith(ecJwk), now })).rejects.toThrow(
      JoseAlgorithmNotAllowedError
    )
  })
})

describe('decodeJwtHeader with a header schema of its own', () => {
  const zKidHeader = z.object({ kid: z.string().optional() }).loose()

  it.each(['none', 'NoNe'])("rejects alg '%s'", (alg) => {
    expect(() => decodeJwtHeader({ jwt: unsignedCompactJws({ alg }, {}), headerSchema: zKidHeader })).toThrow(
      `value may not be 'none'`
    )
  })

  it('rejects a jwk that carries a symmetric key', () => {
    const jwt = unsignedCompactJws({ alg: 'ES256', jwk: { kty: 'oct', k: 'c2VjcmV0' } }, {})

    expect(() => decodeJwtHeader({ jwt, headerSchema: zKidHeader })).toThrow(
      `the jwk contains the private key member 'k'`
    )
  })

  it('returns the header as the schema returned it', () => {
    const jwt = unsignedCompactJws({ alg: 'ES256', kid: 'key-1', typ: 'example+jwt' }, {})

    expect(decodeJwtHeader({ jwt, headerSchema: z.object({ kid: z.string() }) }).header).toEqual({ kid: 'key-1' })
  })
})

describe('decodeJwtHeader of a compact JWE', () => {
  const encode = (value: unknown) => base64url.encode(stringToBytes(JSON.stringify(value)))
  const jwe = (header: Record<string, unknown>) => `${encode(header)}..aXY.Y3Q.dGFn`

  it('rejects a header without enc', () => {
    expect(() => decodeJwtHeader({ jwt: jwe({ alg: 'ECDH-ES' }) })).toThrow(JoseValidationError)
  })

  it('rejects a header without enc when a header schema of its own is given', () => {
    expect(() =>
      decodeJwtHeader({ jwt: jwe({ alg: 'ECDH-ES', kid: 'key-1' }), headerSchema: z.object({ kid: z.string() }) })
    ).toThrow(JoseValidationError)
  })

  it('rejects an ephemeral public key that carries private key material', () => {
    const epk = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', d: 'd' }

    expect(() => decodeJwtHeader({ jwt: jwe({ alg: 'ECDH-ES', enc: 'A256GCM', epk }) })).toThrow(
      `the jwk contains the private key member 'd'`
    )
  })

  it('decodes a header with alg and enc', () => {
    expect(decodeJwtHeader({ jwt: jwe({ alg: 'ECDH-ES', enc: 'A256GCM', kid: 'key-1' }) }).header).toEqual({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      kid: 'key-1',
    })
  })
})

describe('decodeJwtHeader of something that is neither a JWS nor a JWE', () => {
  it('rejects a token with four parts', () => {
    expect(() => decodeJwtHeader({ jwt: 'a.b.c.d' })).toThrow(
      new JoseParseError(
        'Unable to decode the header, the token is neither a compact JWS (three parts) nor a compact JWE (five parts)'
      )
    )
  })
})
