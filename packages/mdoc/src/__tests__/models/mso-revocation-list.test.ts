import 'reflect-metadata'
import { MediaTypes, StatusList, StatusListCwt, StatusType } from '@owf/token-status-list'
import { X509Certificate } from '@peculiar/x509'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, expect, suite, test } from 'vitest'
import {
  CoseKey,
  InvalidRevocationListError,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  SignatureAlgorithm,
  StatusListEntryNotValidError,
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
// it in the unprotected header when a protected x5t binds the leaf. The x5t check itself is
// covered by the tests of `getIntegrityProtectedX5Chain` in @owf/cose.
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
})

// Token Status List § 7 and § 8.3: a status other than Valid is a statement about the credential,
// a list that fails validation is not. The two are told apart by error class, and a status not
// Valid is still an `InvalidRevocationListError`, which it was reported as before.
suite('verifyStatusListToken with an entry that is not Valid', () => {
  const uri = 'https://example.org/status-list'
  const idx = 3

  const verify = async (
    { status, expirationTime = new Date(Date.now() + 3_600_000) }: { status: StatusType; expirationTime?: Date },
    statusListInfo = { uri, idx }
  ) => {
    const statusListCwt = new StatusListCwt({
      payload: { statusList: new StatusList(new Array(10).fill(StatusType.Valid), 2), subject: uri, expirationTime },
      protectedHeaders: ProtectedHeaders.create({
        protectedHeaders: new Map<number, unknown>([
          [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
          [RegisteredCwtHeaderClaimKey.X5Chain, [certificate]],
        ]),
      }),
    })
    statusListCwt.updateStatusList(idx, status)
    const token = await statusListCwt.signAndEncode(
      { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
      { sign: mdocContext.cose.sign1.sign }
    )
    const fetch = (async () =>
      new Response(new Uint8Array(token), {
        headers: { 'Content-Type': MediaTypes.StatusListCwt },
      })) as typeof globalThis.fetch

    return verifyStatusListToken({ statusListInfo, trustedCertificates: [certificate] }, { ...mdocContext, fetch })
  }

  test('Verify a status list with a revoked entry', async () => {
    const verification = verify({ status: StatusType.Invalid })

    await expect(verification).rejects.toThrow(StatusListEntryNotValidError)
    await expect(verification).rejects.toThrow(InvalidRevocationListError)
    await expect(verification).rejects.toThrow(`Status for id '${idx}' is not Valid (0), but is instead '1'`)
    await expect(verification).rejects.toMatchObject({ uri, idx, status: StatusType.Invalid })
  })

  test('Verify a status list with a suspended entry', async () => {
    const verification = verify({ status: StatusType.Suspended })

    await expect(verification).rejects.toThrow(StatusListEntryNotValidError)
    await expect(verification).rejects.toMatchObject({ uri, idx, status: StatusType.Suspended })
  })

  test('Verify an expired status list with a revoked entry', async () => {
    const verification = verify({ status: StatusType.Invalid, expirationTime: new Date(Date.now() - 3_600_000) })

    await expect(verification).rejects.toThrow(InvalidRevocationListError)
    await expect(verification).rejects.not.toThrow(StatusListEntryNotValidError)
  })

  // Unchanged for now: `StatusList.getStatus` throws a plain `Error` for an index outside the list,
  // which is not mapped to `InvalidRevocationListError`.
  test('Verify a status list with an index outside the list', async () => {
    const verification = verify({ status: StatusType.Valid }, { uri, idx: 1000 })

    await expect(verification).rejects.toThrow('Index out of bounds')
    await expect(verification).rejects.not.toThrow(InvalidRevocationListError)
  })
})
