import 'reflect-metadata'
import { MediaTypes, StatusList, StatusListCwt, StatusType } from '@owf/token-status-list'
import { X509Certificate } from '@peculiar/x509'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, expect, suite, test } from 'vitest'
import {
  CoseKey,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  SignatureAlgorithm,
  UnableToExtractX5ChainFromCwtError,
  UnprotectedHeaders,
  UnprotectedX5ChainNotBoundError,
  verifyStatusListToken,
} from '../..'
import { ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK } from '../config'
import { mdocContext } from '../context'

const certificate = new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)
const otherCertificate = new Uint8Array(certificate.length).fill(0x42)

/** COSE_CertHash of `cert` with SHA-256 (RFC 9360, algorithm -16 from RFC 9054). */
const x5tOf = async (cert: Uint8Array) => [
  -16,
  await mdocContext.crypto.digest({ digestAlgorithm: 'SHA-256', bytes: cert }),
]

// ISO/IEC 18013-5 § 12.3.6.3 requires the x5chain in the protected header. RFC 9360 also allows
// it in the unprotected header when a protected x5t binds the leaf.
suite('verifyStatusListToken with an x5chain in the unprotected header', () => {
  const server = setupServer()
  beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
  afterEach(() => server.resetHandlers())
  afterAll(() => server.close())

  const idx = 3

  const mockStatusList = async (
    path: string,
    {
      x5t,
      x5chain = true,
      protectedX5Chain = false,
    }: { x5t?: unknown; x5chain?: boolean | Uint8Array; protectedX5Chain?: boolean }
  ) => {
    const uri = `https://example.org${path}`

    const statusListCwt = new StatusListCwt({
      payload: {
        statusList: new StatusList(new Array(10).fill(StatusType.Valid), 2),
        subject: uri,
        expirationTime: new Date(Date.now() + 3_600_000),
      },
      protectedHeaders: ProtectedHeaders.create({
        protectedHeaders: new Map<number, unknown>([
          [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
          ...(x5t ? [[RegisteredCwtHeaderClaimKey.X5T, x5t] as [number, unknown]] : []),
          ...(protectedX5Chain ? [[RegisteredCwtHeaderClaimKey.X5Chain, [certificate]] as [number, unknown]] : []),
        ]),
      }),
      unprotectedHeaders: UnprotectedHeaders.create({
        unprotectedHeaders: new Map<number, unknown>(
          x5chain ? [[RegisteredCwtHeaderClaimKey.X5Chain, [x5chain === true ? certificate : x5chain]]] : []
        ),
      }),
    })

    const token = await statusListCwt.signAndEncode(
      { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
      { sign: mdocContext.cose.sign1.sign }
    )

    server.use(
      http.get(
        uri,
        () => new HttpResponse(new Uint8Array(token), { headers: { 'Content-Type': MediaTypes.StatusListCwt } })
      )
    )

    return uri
  }

  const verify = (uri: string) =>
    verifyStatusListToken({ statusListInfo: { uri, idx }, trustedCertificates: [certificate] }, mdocContext)

  test('Verify a status list with an unprotected x5chain bound by a protected x5t', async () => {
    const uri = await mockStatusList('/bound', { x5t: await x5tOf(certificate) })

    const { statusListCwt, chain } = await verify(uri)

    expect(statusListCwt.payload.statusList.getStatus(idx)).toBe(StatusType.Valid)
    expect(chain?.[0]).toEqual(certificate)
  })

  test('Verify a status list without an x5chain', async () => {
    const uri = await mockStatusList('/no-x5chain', { x5t: await x5tOf(certificate), x5chain: false })

    await expect(verify(uri)).rejects.toThrow(UnableToExtractX5ChainFromCwtError)
  })

  test('Verify a status list with an unprotected x5chain and no protected x5t', async () => {
    const uri = await mockStatusList('/unbound', {})

    await expect(verify(uri)).rejects.toThrow(UnprotectedX5ChainNotBoundError)
  })

  test('Verify a status list with an unprotected x5chain and a malformed x5t', async () => {
    const uri = await mockStatusList('/malformed-x5t', { x5t: [-16] })

    await expect(verify(uri)).rejects.toThrow(UnprotectedX5ChainNotBoundError)
  })

  test('Verify a status list with an x5chain in both headers', async () => {
    // The protected chain is used; the unbound unprotected one is ignored.
    const uri = await mockStatusList('/both', { protectedX5Chain: true, x5chain: otherCertificate })

    const { chain } = await verify(uri)

    expect(chain?.[0]).toEqual(certificate)
  })

  test('Verify a status list with an unprotected x5chain and the x5t of another certificate', async () => {
    const uri = await mockStatusList('/mismatch', { x5t: await x5tOf(otherCertificate) })

    await expect(verify(uri)).rejects.toThrow(UnprotectedX5ChainNotBoundError)
  })

  test('Verify a status list with an unprotected x5chain and an x5t with an unsupported hash algorithm', async () => {
    const [, hash] = await x5tOf(certificate)
    // SHA-512 (-44), registered for COSE_CertHash but not supported here.
    const uri = await mockStatusList('/unsupported-hash', { x5t: [-44, hash] })

    await expect(verify(uri)).rejects.toThrow(UnprotectedX5ChainNotBoundError)
  })
})
