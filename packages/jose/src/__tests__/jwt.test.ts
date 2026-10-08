import { dateToSeconds } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import z from 'zod'
import { decodeJwt, decodeJwtHeader } from '../jwt/decode-jwt'
import { signJwt } from '../jwt/sign-jwt'
import { verifyJwt } from '../jwt/verify-jwt'
import { verifyJwtClaims } from '../jwt/verify-jwt-claims'
import { zJwtHeader, zJwtPayload } from '../jwt/z-jwt'
import { zJoseType } from '../utils/z-common'
import { createEs256Context, unsignedCompactJws } from './context'

const now = new Date('2026-09-15T12:00:00Z')
const inSeconds = (date: Date) => dateToSeconds(date)
const minutes = (count: number) => count * 60

describe('decodeJwt', () => {
  it('validates the registered claims even when a custom payload schema is given', () => {
    // A schema that only describes `vct` must not be able to leave `exp` unchecked
    const zVctPayload = z.object({ vct: z.string() }).loose()
    const jwt = unsignedCompactJws({ alg: 'ES256' }, { vct: 'https://example.com/card', exp: 'not-a-number' })

    expect(() => decodeJwt({ jwt, payloadSchema: zVctPayload })).toThrow('Invalid JWT payload')
  })

  it('rejects a JWT with an unencoded payload', () => {
    const jwt = unsignedCompactJws({ alg: 'ES256', b64: false, crit: ['b64'] }, {})

    expect(() => decodeJwt({ jwt, understoodCriticalParameters: ['b64'] })).toThrow(`sets 'b64' to false`)
  })

  it('decodes only the header of a compact JWE', () => {
    const { header } = decodeJwtHeader({ jwt: 'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9..aXY.Y3Q.dGFn' })

    expect(header.alg).toBe('ECDH-ES')
  })
})

describe('schema composition', () => {
  // What a key binding JWT must look like, expressed as a schema rather than as a list of checks
  const zKeyBindingJwtHeader = z.object({ ...zJwtHeader.shape, typ: zJoseType('kb+jwt') }).loose()
  const zKeyBindingJwtPayload = z
    .object({
      ...zJwtPayload.shape,
      iat: z.number(),
      aud: z.string(),
      nonce: z.string(),
      sd_hash: z.string().min(1),
    })
    .loose()

  const payload = { iat: inSeconds(now), aud: 'https://verifier.example', nonce: 'n-1', sd_hash: 'abc' }

  it('accepts a valid key binding JWT', () => {
    const jwt = unsignedCompactJws({ alg: 'ES256', typ: 'kb+jwt' }, payload)
    const decoded = decodeJwt({ jwt, headerSchema: zKeyBindingJwtHeader, payloadSchema: zKeyBindingJwtPayload })

    expect(decoded.payload.sd_hash).toBe('abc')
  })

  it('accepts the media type with its application prefix, as RFC 7515 allows', () => {
    const jwt = unsignedCompactJws({ alg: 'ES256', typ: 'application/kb+jwt' }, payload)

    expect(() => decodeJwt({ jwt, headerSchema: zKeyBindingJwtHeader })).not.toThrow()
  })

  it('rejects a token of a different type', () => {
    const jwt = unsignedCompactJws({ alg: 'ES256', typ: 'dpop+jwt' }, payload)

    expect(() => decodeJwt({ jwt, headerSchema: zKeyBindingJwtHeader })).toThrow(`media type to be 'kb+jwt'`)
  })

  it('rejects a key binding JWT with an empty sd_hash', () => {
    const jwt = unsignedCompactJws({ alg: 'ES256', typ: 'kb+jwt' }, { ...payload, sd_hash: '' })

    expect(() => decodeJwt({ jwt, payloadSchema: zKeyBindingJwtPayload })).toThrow('Invalid JWT payload')
  })

  it('rejects a key binding JWT that is missing a claim', () => {
    const { nonce: _nonce, ...withoutNonce } = payload
    const jwt = unsignedCompactJws({ alg: 'ES256', typ: 'kb+jwt' }, withoutNonce)

    expect(() => decodeJwt({ jwt, payloadSchema: zKeyBindingJwtPayload })).toThrow('Invalid JWT payload')
  })
})

describe('verifyJwtClaims', () => {
  it('accepts a token within its validity window', () => {
    expect(() =>
      verifyJwtClaims(
        { iat: inSeconds(now), nbf: inSeconds(now), exp: inSeconds(new Date(now.getTime() + minutes(5) * 1000)) },
        { now }
      )
    ).not.toThrow()
  })

  it('rejects an expired token', () => {
    const exp = inSeconds(new Date(now.getTime() - minutes(5) * 1000))

    expect(() => verifyJwtClaims({ exp }, { now })).toThrow(`The 'exp' claim`)
  })

  it('accepts a token that expired within the clock skew', () => {
    const exp = inSeconds(new Date(now.getTime() - 10 * 1000))

    expect(() => verifyJwtClaims({ exp }, { now })).not.toThrow()
    expect(() => verifyJwtClaims({ exp }, { now, skewSeconds: 0 })).toThrow(`The 'exp' claim`)
  })

  it('rejects a token that is not valid yet', () => {
    const nbf = inSeconds(new Date(now.getTime() + minutes(5) * 1000))

    expect(() => verifyJwtClaims({ nbf }, { now })).toThrow(`The 'nbf' claim`)
  })

  it('rejects a token issued in the future', () => {
    const iat = inSeconds(new Date(now.getTime() + minutes(5) * 1000))

    expect(() => verifyJwtClaims({ iat }, { now })).toThrow(`The 'iat' claim`)
    expect(() => verifyJwtClaims({ iat }, { now, checkIssuedAt: false })).not.toThrow()
  })

  it('rejects a token older than maxAgeSeconds, and one without iat', () => {
    const iat = inSeconds(new Date(now.getTime() - minutes(5) * 1000))

    expect(() => verifyJwtClaims({ iat }, { now, skewSeconds: 0, maxAgeSeconds: minutes(10) })).not.toThrow()
    expect(() => verifyJwtClaims({ iat }, { now, skewSeconds: 0, maxAgeSeconds: minutes(1) })).toThrow(
      expect.objectContaining({ claim: 'iat', reason: 'expired' })
    )
    // The skew applies, as it does to `exp`
    expect(() => verifyJwtClaims({ iat }, { now, skewSeconds: minutes(5), maxAgeSeconds: minutes(1) })).not.toThrow()
    expect(() => verifyJwtClaims({}, { now, maxAgeSeconds: minutes(1) })).toThrow(
      expect.objectContaining({ claim: 'iat', reason: 'missing' })
    )
  })

  it('checks the expected issuer, subject and nonce', () => {
    const payload = { iss: 'https://issuer.example', sub: 'subject', nonce: 'n-1' }

    expect(() => verifyJwtClaims(payload, { now, expectedIssuer: 'https://issuer.example' })).not.toThrow()
    expect(() => verifyJwtClaims(payload, { now, expectedIssuer: 'https://other.example' })).toThrow(`The 'iss' claim`)
    expect(() => verifyJwtClaims(payload, { now, expectedSubject: 'other' })).toThrow(`The 'sub' claim`)
    expect(() => verifyJwtClaims(payload, { now, expectedNonce: 'n-2' })).toThrow(`The 'nonce' claim`)
  })

  it('accepts a token when any of its audiences is expected', () => {
    const payload = { aud: ['https://a.example', 'https://b.example'] }

    expect(() => verifyJwtClaims(payload, { now, expectedAudience: 'https://b.example' })).not.toThrow()
    expect(() => verifyJwtClaims(payload, { now, expectedAudience: 'https://c.example' })).toThrow(`The 'aud' claim`)
  })

  it('rejects a time claim that is not a NumericDate', () => {
    // Only reachable for a payload that was not parsed with `zJwtPayload`, which is what a cast
    // gets you. Skipping the claim instead would accept a token whose validity was never checked.
    const exp = '1700000000' as unknown as number

    expect(() => verifyJwtClaims({ exp }, { now })).toThrow(`The 'exp' claim '1700000000' is not a NumericDate`)
    expect(() => verifyJwtClaims({ exp }, { now, checkExpirationTime: false })).not.toThrow()
    expect(() => verifyJwtClaims({ nbf: exp }, { now })).toThrow(`The 'nbf' claim`)
    expect(() => verifyJwtClaims({ iat: exp }, { now })).toThrow(`The 'iat' claim`)
  })

  it('requires the claims the caller lists', () => {
    expect(() => verifyJwtClaims({ iss: 'https://issuer.example' }, { now, requiredClaims: ['iss'] })).not.toThrow()
    expect(() => verifyJwtClaims({}, { now, requiredClaims: ['iss'] })).toThrow(`has no 'iss' claim, which is required`)
  })
})

describe('signJwt and verifyJwt', () => {
  it('signs and verifies a JWT', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()
    const signer = { method: 'jwk', alg: 'ES256', publicJwk } as const

    const { jwt, header } = await signJwt({
      header: { typ: 'example+jwt' },
      payload: { iss: 'https://issuer.example', iat: inSeconds(now) },
      signer,
      signJwsCallback: signJws,
    })

    expect(header).toEqual({ typ: 'example+jwt', alg: 'ES256' })

    const verified = await verifyJwt({
      jwt,
      verifyJwsCallback: verifyJws,
      now,
      expectedIssuer: 'https://issuer.example',
    })

    expect(verified.payload.iss).toBe('https://issuer.example')
    expect(verified.signer.publicJwk).toEqual(publicJwk)
  })

  it('validates the header and the claims set against the schemas of the token type', async () => {
    const { signJws, publicJwk } = await createEs256Context()
    const signer = { method: 'jwk', alg: 'ES256', publicJwk } as const

    const zKeyBindingJwtHeader = z.object({ ...zJwtHeader.shape, typ: zJoseType('kb+jwt') }).loose()
    const zKeyBindingJwtPayload = z
      .object({ ...zJwtPayload.shape, iat: z.number(), aud: z.string(), nonce: z.string(), sd_hash: z.string().min(1) })
      .loose()

    const valid = { iat: inSeconds(now), aud: 'https://verifier.example', nonce: 'n-1', sd_hash: 'abc' }
    const schemas = { headerSchema: zKeyBindingJwtHeader, payloadSchema: zKeyBindingJwtPayload } as const

    // `alg` and `jwk` are not given: they come from the signer
    const { payload } = await signJwt({
      header: { typ: 'kb+jwt' },
      payload: valid,
      ...schemas,
      signer,
      signJwsCallback: signJws,
    })
    expect(payload.sd_hash).toBe('abc')

    // The claim is missing, which a verifier would reject: better to find out here
    const { sd_hash: _sdHash, ...withoutSdHash } = valid
    await expect(
      // @ts-expect-error the missing claim is a type error as well as a validation error
      signJwt({ header: { typ: 'kb+jwt' }, payload: withoutSdHash, ...schemas, signer, signJwsCallback: signJws })
    ).rejects.toThrow('invalid claims set')

    await expect(
      signJwt({ header: { typ: 'dpop+jwt' }, payload: valid, ...schemas, signer, signJwsCallback: signJws })
    ).rejects.toThrow('invalid header')
  })

  it('types the header and the claims set from the schemas', async () => {
    const { signJws, publicJwk } = await createEs256Context()
    const zHeader = z.object({ ...zJwtHeader.shape, typ: zJoseType('kb+jwt') }).loose()
    const zPayload = z.object({ ...zJwtPayload.shape, sd_hash: z.string() }).loose()

    const options = {
      headerSchema: zHeader,
      payloadSchema: zPayload,
      signJwsCallback: signJws,
      signer: { method: 'jwk', alg: 'ES256', publicJwk } as const,
    }

    // `alg` and `jwk` come from a jwk signer, so neither has to be given...
    await signJwt({ ...options, header: { typ: 'kb+jwt' }, payload: { sd_hash: 'abc' } })
    // ...and passing them anyway is allowed, they are simply overridden
    await signJwt({ ...options, header: { typ: 'kb+jwt', alg: 'ES256', jwk: publicJwk }, payload: { sd_hash: 'abc' } })
    // `kid` is not derived from a jwk signer, so it is the caller's to set
    await signJwt({ ...options, header: { typ: 'kb+jwt', kid: 'key-1' }, payload: { sd_hash: 'abc' } })

    // @ts-expect-error a header parameter the schema requires is still required
    await expect(signJwt({ ...options, header: {}, payload: { sd_hash: 'abc' } })).rejects.toThrow()
    // @ts-expect-error a claim the schema requires is still required
    await expect(signJwt({ ...options, header: { typ: 'kb+jwt' }, payload: {} })).rejects.toThrow()
    // @ts-expect-error and the members that are given have to have the right type
    await expect(signJwt({ ...options, header: { typ: 'kb+jwt' }, payload: { sd_hash: 1 } })).rejects.toThrow()
  })

  it('validates against the registered claims even when a custom payload schema is given', async () => {
    const { signJws, publicJwk } = await createEs256Context()

    await expect(
      signJwt({
        payload: { vct: 'https://example.com/card', exp: 'not-a-number' },
        payloadSchema: z.object({ vct: z.string() }).loose(),
        signer: { method: 'jwk', alg: 'ES256', publicJwk },
        signJwsCallback: signJws,
      })
    ).rejects.toThrow('invalid claims set')
  })

  it('signs what the schema validated', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()

    // A schema that fills in a claim shapes the token, rather than being checked and then discarded
    const zWithDefault = z.object({ ...zJwtPayload.shape, iss: z.string().default('https://issuer.example') }).loose()

    const { jwt } = await signJwt({
      payload: {},
      payloadSchema: zWithDefault,
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
    })

    const verified = await verifyJwt({ jwt, verifyJwsCallback: verifyJws, now })
    expect(verified.payload.iss).toBe('https://issuer.example')
  })

  it('rejects a JWT whose payload was tampered with', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()

    const { jwt } = await signJwt({
      payload: { iss: 'https://issuer.example' },
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
    })

    const [header, , signature] = jwt.split('.')
    const tampered = `${header}.${unsignedCompactJws({}, { iss: 'https://attacker.example' }).split('.')[1]}.${signature}`

    await expect(verifyJwt({ jwt: tampered, verifyJwsCallback: verifyJws, now })).rejects.toThrow(
      'Error during verification of the JWT'
    )
  })

  it('verifies the signature before the claims', async () => {
    const { verifyJws } = await createEs256Context()
    const jwt = unsignedCompactJws({ alg: 'ES256' }, { exp: inSeconds(new Date(now.getTime() - minutes(60) * 1000)) })

    // The token is expired as well, but it is the signature that must be reported: the claims of a
    // token whose signer has not been established mean nothing.
    await expect(verifyJwt({ jwt, verifyJwsCallback: verifyJws, now })).rejects.toThrow(
      'Error during verification of the JWT'
    )
  })

  it('verifies an already decoded JWT', async () => {
    const { signJws, verifyJws, publicJwk } = await createEs256Context()

    const { jwt } = await signJwt({
      payload: { iss: 'https://issuer.example' },
      signer: { method: 'jwk', alg: 'ES256', publicJwk },
      signJwsCallback: signJws,
    })

    const decoded = decodeJwt({ jwt })
    const verified = await verifyJwt({ jwt: decoded, verifyJwsCallback: verifyJws, now })

    expect(verified.compact).toBe(jwt)
  })
})
