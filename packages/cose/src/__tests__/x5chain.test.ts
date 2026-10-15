import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, test } from 'vitest'
import {
  CoseX5ChainNotBoundError,
  getIntegrityProtectedX5Chain,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  Sign1,
  SignatureAlgorithm,
  UnprotectedHeaders,
  type X5ChainContext,
} from '../../src'

const ctx: X5ChainContext = { digest: ({ bytes }) => sha256(bytes) }

const certificate = new Uint8Array(32).fill(0x01)
const otherCertificate = new Uint8Array(32).fill(0x02)

const sign1 = ({
  protectedX5Chain,
  unprotectedX5Chain,
  x5t,
}: {
  protectedX5Chain?: Uint8Array | Uint8Array[]
  unprotectedX5Chain?: Uint8Array | Uint8Array[]
  x5t?: unknown
}) =>
  Sign1.create({
    protectedHeaders: ProtectedHeaders.create({
      protectedHeaders: new Map<number, unknown>([
        [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
        ...(protectedX5Chain ? [[RegisteredCwtHeaderClaimKey.X5Chain, protectedX5Chain] as [number, unknown]] : []),
        ...(x5t ? [[RegisteredCwtHeaderClaimKey.X5T, x5t] as [number, unknown]] : []),
      ]),
    }),
    unprotectedHeaders: UnprotectedHeaders.create({
      unprotectedHeaders: new Map<number, unknown>(
        unprotectedX5Chain ? [[RegisteredCwtHeaderClaimKey.X5Chain, unprotectedX5Chain]] : []
      ),
    }),
    payload: new Uint8Array([0x01]),
  })

describe('getIntegrityProtectedX5Chain', () => {
  test('returns the x5chain of the protected header', async () => {
    const chain = await getIntegrityProtectedX5Chain(sign1({ protectedX5Chain: [certificate] }), ctx)

    expect(chain).toEqual([certificate])
  })

  test('returns a single certificate as a chain', async () => {
    const chain = await getIntegrityProtectedX5Chain(sign1({ protectedX5Chain: certificate }), ctx)

    expect(chain).toEqual([certificate])
  })

  test('prefers the protected header over an unbound unprotected one', async () => {
    const chain = await getIntegrityProtectedX5Chain(
      sign1({ protectedX5Chain: [certificate], unprotectedX5Chain: [otherCertificate] }),
      ctx
    )

    expect(chain).toEqual([certificate])
  })

  test('returns the x5chain of the unprotected header when a protected x5t matches its leaf', async () => {
    const chain = await getIntegrityProtectedX5Chain(
      sign1({ unprotectedX5Chain: [certificate, otherCertificate], x5t: [-16, sha256(certificate)] }),
      ctx
    )

    expect(chain).toEqual([certificate, otherCertificate])
  })

  test('returns undefined without an x5chain', async () => {
    const chain = await getIntegrityProtectedX5Chain(sign1({ x5t: [-16, sha256(certificate)] }), ctx)

    expect(chain).toBeUndefined()
  })

  test('rejects an unprotected x5chain without a protected x5t', async () => {
    await expect(getIntegrityProtectedX5Chain(sign1({ unprotectedX5Chain: [certificate] }), ctx)).rejects.toThrow(
      CoseX5ChainNotBoundError
    )
  })

  test('rejects an unprotected x5chain with a malformed x5t', async () => {
    await expect(
      getIntegrityProtectedX5Chain(sign1({ unprotectedX5Chain: [certificate], x5t: [-16] }), ctx)
    ).rejects.toThrow(CoseX5ChainNotBoundError)
  })

  test('rejects an unprotected x5chain with the x5t of another certificate', async () => {
    await expect(
      getIntegrityProtectedX5Chain(
        sign1({ unprotectedX5Chain: [certificate], x5t: [-16, sha256(otherCertificate)] }),
        ctx
      )
    ).rejects.toThrow(CoseX5ChainNotBoundError)
  })

  test('rejects an unprotected x5chain with an x5t with an unsupported hash algorithm', async () => {
    // SHA-512 (-44), registered for COSE_CertHash but not supported here.
    await expect(
      getIntegrityProtectedX5Chain(sign1({ unprotectedX5Chain: [certificate], x5t: [-44, sha256(certificate)] }), ctx)
    ).rejects.toThrow(CoseX5ChainNotBoundError)
  })
})
