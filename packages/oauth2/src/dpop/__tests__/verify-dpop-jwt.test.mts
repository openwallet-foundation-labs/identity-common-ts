import { calculateJwkThumbprint, JoseInvalidArgumentError, JoseValidationError, type Jwk } from '@owf/jose'
import { describe, expect, test } from 'vitest'
import { callbacks, getSignJwsCallback } from '../../__tests__/util.mjs'
import { Oauth2ServerErrorResponseError } from '../../error/Oauth2ServerErrorResponseError'
import { createDpopJwt, verifyDpopJwt } from '../dpop'
import { zDpopJwtHeader } from '../z-dpop'

const request = {
  method: 'POST',
  url: 'https://authorization-server.com/token',
  headers: new Headers(),
} as const

const dpopSignerJwk = {
  kty: 'EC',
  d: 'UxBOEoXuH9qlZ0Bo2E1sCuZDkAzVl99eenarvWMrgH0',
  crv: 'P-256',
  x: 'BvowcNvKitnPOIU7EQSP6mvHG46mqJp1iVEeaHRkzMQ',
  y: 'h2kx9opNMxfK1_mcx2t5SIPf-kg4oNXS77tBxDvy1TM',
} satisfies Jwk

const otherSignerJwk = {
  kty: 'EC',
  d: '6xn3gj1pQisseLDhd1qtGbBr9oWBwxxvAMBSDerbSzk',
  crv: 'P-256',
  x: 'CQHN_Jmxy4yDZzDmudBArRip9DtU8bpNDdtya7yj6f4',
  y: 'sDsPt93iLO7eZdt0-qVwD3bRAaG1V_3wmYdw3dr_lfs',
} satisfies Jwk

const { d: _, ...dpopSignerPublicJwk } = dpopSignerJwk
const { d: __, ...otherSignerPublicJwk } = otherSignerJwk

describe('verifyDpopJwt', () => {
  test('verifies a valid proof with matching expected jwk thumbprint', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJws: getSignJwsCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    const expectedJwkThumbprint = await calculateJwkThumbprint({
      hashAlgorithm: 'sha-256',
      hashCallback: callbacks.hash,
      jwk: dpopSignerPublicJwk,
    })

    const result = await verifyDpopJwt({
      callbacks,
      dpopJwt,
      request,
      expectedJwkThumbprint,
      allowedSigningAlgs: ['ES256'],
    })

    expect(result.jwkThumbprint).toBe(expectedJwkThumbprint)
  })

  test('rejects proofs signed by the wrong key', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJws: getSignJwsCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    const expectedJwkThumbprint = await calculateJwkThumbprint({
      hashAlgorithm: 'sha-256',
      hashCallback: callbacks.hash,
      jwk: otherSignerPublicJwk,
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        expectedJwkThumbprint,
      })
    ).rejects.toThrow('expect jwk thumbprint value')
  })

  test('rejects proofs with wrong HTTP method', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJws: getSignJwsCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request: {
          ...request,
          method: 'GET',
        },
      })
    ).rejects.toThrow("expected htm value 'GET'")
  })

  test('rejects proofs with wrong URL', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJws: getSignJwsCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request: {
          ...request,
          url: 'https://authorization-server.com/another-endpoint',
        },
      })
    ).rejects.toThrow("expected htu value 'https://authorization-server.com/another-endpoint'")
  })

  test.each([
    'https://authorization-server.com/token?query=value',
    'https://authorization-server.com/token#fragment',
    'https://AUTHORIZATION-SERVER.COM/token',
    'https://authorization-server.com:443/token',
    'HTTPS://authorization-server.com/token',
  ])('accepts proofs with htu %s that is equivalent to the request url', async (htu) => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJws: getSignJwsCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
      additionalPayload: { htu },
    })

    await expect(verifyDpopJwt({ callbacks, dpopJwt, request })).resolves.toBeDefined()
  })

  test('rejects proofs with htu that differs in path case', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJws: getSignJwsCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
      additionalPayload: { htu: 'https://authorization-server.com/TOKEN' },
    })

    await expect(verifyDpopJwt({ callbacks, dpopJwt, request })).rejects.toThrow(
      "Dpop jwt contains htu value 'https://authorization-server.com/TOKEN'"
    )
  })

  test('rejects stale proofs when maxProofAgeSeconds is exceeded', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJws: getSignJwsCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
      issuedAt: new Date('2024-01-01T00:00:00.000Z'),
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        now: new Date('2024-01-01T00:02:00.000Z'),
        maxProofAgeSeconds: 30,
      })
    ).rejects.toThrow(/iat: .* \(expired\)/)
  })

  test('adds the allowed skew to maxProofAgeSeconds, 30 seconds by default', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: { ...callbacks, signJws: getSignJwsCallback([dpopSignerJwk]) },
      request,
      signer: { method: 'jwk', alg: 'ES256', publicJwk: dpopSignerPublicJwk },
      issuedAt: new Date('2024-01-01T00:00:00.000Z'),
    })

    const verify = (allowedSkewInSeconds?: number) =>
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        now: new Date('2024-01-01T00:00:45.000Z'),
        maxProofAgeSeconds: 30,
        allowedSkewInSeconds,
      })

    await expect(verify()).resolves.toBeDefined()
    await expect(verify(0)).rejects.toThrow(/iat: .* \(expired\)/)
  })

  test('applies allowedSkewInSeconds to a proof issued in the future', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJws: getSignJwsCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
      issuedAt: new Date('2024-01-01T00:00:45.000Z'),
    })

    const verify = (allowedSkewInSeconds: number) =>
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        now: new Date('2024-01-01T00:00:00.000Z'),
        maxProofAgeSeconds: 30,
        allowedSkewInSeconds,
      })

    // A skew larger than the 30 seconds `verifyJwt` allows by default is honoured for `iat` as well
    await expect(verify(60)).resolves.toBeDefined()
    await expect(verify(30)).rejects.toThrow('in the future')
  })

  test('rejects replayed jti values when uniqueness callback indicates replay', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJws: getSignJwsCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    const seenJti = new Set<string>()
    const assertJtiUniqueness = ({
      header,
      payload,
      compact,
    }: {
      header: { typ: string }
      payload: { jti: string }
      compact: string
    }) => {
      expect(header.typ).toBe('dpop+jwt')
      expect(compact).toBe(dpopJwt)

      if (seenJti.has(payload.jti)) return false
      seenJti.add(payload.jti)
      return true
    }

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        assertJtiUniqueness,
      })
    ).resolves.toBeDefined()

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        assertJtiUniqueness,
      })
    ).rejects.toThrow('already been used')
  })

  test('checks the jti for replay only after the signature verifies', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJws: getSignJwsCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })
    const [header, payload, signature] = dpopJwt.split('.')
    const tampered = `${header}.${payload}.${signature.startsWith('A') ? 'B' : 'A'}${signature.slice(1)}`

    let replayChecks = 0
    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt: tampered,
        request,
        assertJtiUniqueness: () => {
          replayChecks++
          return true
        },
      })
    ).rejects.toThrow()
    expect(replayChecks).toBe(0)
  })

  test('rejects missing nonce when nonce is expected', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJws: getSignJwsCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        expectedNonce: 'nonce-1',
      })
    ).rejects.toThrow(/nonce: .* \(claim_missing\)/)
  })

  test('rejects invalid nonce values', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJws: getSignJwsCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
      nonce: 'actual-nonce',
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        expectedNonce: 'different-nonce',
      })
    ).rejects.toThrow(/nonce: .* \(claim_value_mismatch\)/)
  })

  test('keeps the JoseValidationError as cause, so a caller can tell a wrong nonce from other failures', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: { ...callbacks, signJws: getSignJwsCallback([dpopSignerJwk]) },
      request,
      signer: { method: 'jwk', alg: 'ES256', publicJwk: dpopSignerPublicJwk },
      nonce: 'actual-nonce',
    })

    const error = await verifyDpopJwt({ callbacks, dpopJwt, request, expectedNonce: 'different-nonce' }).catch((e) => e)
    expect(error).toBeInstanceOf(Oauth2ServerErrorResponseError)
    expect(error.cause).toBeInstanceOf(JoseValidationError)
    expect(error.cause.findIssue('claim_value_mismatch')).toMatchObject({ path: ['nonce'] })
  })

  test('rejects a proof issued more than the skew in the future, also without maxProofAgeSeconds', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: { ...callbacks, signJws: getSignJwsCallback([dpopSignerJwk]) },
      request,
      signer: { method: 'jwk', alg: 'ES256', publicJwk: dpopSignerPublicJwk },
      issuedAt: new Date('2024-01-01T00:01:00.000Z'),
    })

    await expect(
      verifyDpopJwt({ callbacks, dpopJwt, request, now: new Date('2024-01-01T00:00:00.000Z') })
    ).rejects.toThrow('in the future')
  })

  test('throws a negative allowedSkewInSeconds as the mistake of the caller, not as an invalid proof', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: { ...callbacks, signJws: getSignJwsCallback([dpopSignerJwk]) },
      request,
      signer: { method: 'jwk', alg: 'ES256', publicJwk: dpopSignerPublicJwk },
    })

    await expect(verifyDpopJwt({ callbacks, dpopJwt, request, allowedSkewInSeconds: -1 })).rejects.toBeInstanceOf(
      JoseInvalidArgumentError
    )
  })

  test('rejects unsupported proof algorithms', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJws: getSignJwsCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        allowedSigningAlgs: ['ES384'],
      })
    ).rejects.toThrow('allowed dpop signging alg values are ES384')
  })

  test('accepts the dpop+jwt typ in its full media type form and in any casing (RFC 7515 section 4.1.9)', () => {
    const header = { alg: 'ES256', jwk: dpopSignerPublicJwk }
    for (const typ of ['dpop+jwt', 'application/dpop+jwt', 'DPoP+JWT']) {
      expect(zDpopJwtHeader.safeParse({ ...header, typ }).success).toBe(true)
    }
    expect(zDpopJwtHeader.safeParse({ ...header, typ: 'jwt' }).success).toBe(false)
  })
})
