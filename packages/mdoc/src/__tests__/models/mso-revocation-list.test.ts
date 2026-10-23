import 'reflect-metadata'
import { base64, base64url, stringToBytes } from '@owf/identity-common'
import { type BitsPerStatus, MediaTypes, StatusList, StatusListCwt, StatusType } from '@owf/token-status-list'
import { X509Certificate } from '@peculiar/x509'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, expect, suite, test } from 'vitest'
import {
  CoseKey,
  InvalidRevocationListError,
  InvalidSignatureError,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  SignatureAlgorithm,
  StatusListEntryNotValidError,
  UnableToExtractX5ChainFromCwtError,
  UnableToExtractX5ChainFromJwtError,
  UnprotectedHeaders,
  UnprotectedX5ChainNotBoundError,
  verifyStatusListToken,
} from '../..'
import { INVALID_CERTIFICATE, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK } from '../config'
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

    expect(statusListCwt?.payload.statusList.getStatus(idx)).toBe(StatusType.Valid)
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

// ISO/IEC 18013-5 § 12.3.6.3 requires a CWT, so it is requested first. A list served as a JWT is
// accepted as a fallback, to the same rules.
suite('verifyStatusListToken with a status list in JWT format', () => {
  const server = setupServer()
  beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
  afterEach(() => server.resetHandlers())
  afterAll(() => server.close())

  const idx = 3
  const nowSeconds = Math.floor(Date.now() / 1000)
  const encodeJson = (value: unknown) => base64url.encode(stringToBytes(JSON.stringify(value)))

  const mockStatusList = async (
    path: string,
    {
      status = StatusType.Valid,
      bits = 1,
      header = {},
      payload = {},
      tamper = false,
      encodedSignature,
      rawHeader,
      rawPayload,
    }: {
      status?: number
      bits?: BitsPerStatus
      header?: Record<string, unknown>
      payload?: Record<string, unknown>
      tamper?: boolean
      encodedSignature?: string
      /** Replaces the whole header or payload, e.g. with a JSON value that is not an object. */
      rawHeader?: unknown
      rawPayload?: unknown
    } = {}
  ) => {
    const uri = `https://example.org${path}`
    const statusList = new StatusList(new Array(10).fill(StatusType.Valid), bits)
    statusList.setStatus(idx, status)

    const signingInput = `${encodeJson(
      rawHeader !== undefined
        ? rawHeader
        : { alg: 'ES256', typ: 'statuslist+jwt', x5c: [base64.encode(certificate)], ...header }
    )}.${encodeJson(
      rawPayload !== undefined
        ? rawPayload
        : {
            sub: uri,
            iat: nowSeconds - 60,
            exp: nowSeconds + 3600,
            status_list: { bits, lst: base64url.encode(statusList.compressStatusListToBytes()) },
            ...payload,
          }
    )}`
    const signature = await mdocContext.cose.sign1.sign({
      toBeSigned: stringToBytes(signingInput),
      key: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      algorithm: SignatureAlgorithm.ES256,
    })
    if (tamper) signature[0] ^= 0xff

    server.use(
      http.get(
        uri,
        () =>
          new HttpResponse(`${signingInput}.${encodedSignature ?? base64url.encode(signature)}`, {
            headers: { 'Content-Type': MediaTypes.StatusListJwt },
          })
      )
    )

    return uri
  }

  const verify = (uri: string, options: { trustedCertificates?: Uint8Array[]; disable?: boolean } = {}) =>
    verifyStatusListToken(
      {
        statusListInfo: { uri, idx },
        trustedCertificates: options.disable ? undefined : (options.trustedCertificates ?? [certificate]),
        disableCertificateChainValidation: options.disable,
      },
      mdocContext
    )

  test('Verify a JWT status list with a Valid entry', async () => {
    const { statusListJwt, statusListCwt, chain } = await verify(await mockStatusList('/valid'))

    expect(statusListJwt?.statusList.getStatus(idx)).toBe(StatusType.Valid)
    expect(statusListCwt).toBeUndefined()
    expect(chain?.[0]).toEqual(certificate)
  })

  test('Verify a JWT status list without certificate chain validation', async () => {
    const { statusListJwt, chain } = await verify(await mockStatusList('/no-chain-validation'), { disable: true })

    expect(statusListJwt?.statusList.getStatus(idx)).toBe(StatusType.Valid)
    expect(chain).toBeUndefined()
  })

  test.each([
    { name: 'a revoked entry', bits: 1 as const, status: StatusType.Invalid },
    { name: 'a suspended entry in a 2-bit list', bits: 2 as const, status: StatusType.Suspended },
    { name: 'an entry of status 3 in a 2-bit list', bits: 2 as const, status: 3 },
  ])('Verify a JWT status list with $name', async ({ bits, status }) => {
    const uri = await mockStatusList(`/not-valid-${status}`, { bits, status })
    const verification = verify(uri)

    await expect(verification).rejects.toThrow(StatusListEntryNotValidError)
    await expect(verification).rejects.toMatchObject({ uri, idx, status })
  })

  // Every list below carries a revoked entry, so a missing check would surface as a status.
  test.each([
    { name: 'a wrong typ', options: { header: { typ: 'JWT' } }, error: InvalidRevocationListError },
    { name: 'no exp', options: { payload: { exp: undefined } }, error: InvalidRevocationListError },
    { name: 'an expired exp', options: { payload: { exp: nowSeconds - 3600 } }, error: InvalidRevocationListError },
    {
      name: 'a sub mismatch',
      options: { payload: { sub: 'https://example.org/other' } },
      error: InvalidRevocationListError,
    },
    { name: 'a tampered signature', options: { tamper: true }, error: InvalidSignatureError },
    {
      name: 'a signature that is too short',
      options: { encodedSignature: base64url.encode(new Uint8Array(10)) },
      error: InvalidSignatureError,
    },
    // ECDSA signatures in DER, as some signers produce, start with a SEQUENCE (0x30) and are 70-72 bytes.
    {
      name: 'a DER-encoded signature',
      options: { encodedSignature: base64url.encode(new Uint8Array([0x30, 0x44, ...new Array(68).fill(1)])) },
      error: InvalidSignatureError,
    },
    {
      name: 'a signature that is not base64url',
      options: { encodedSignature: '!!!' },
      error: InvalidRevocationListError,
    },
    { name: 'a crit header', options: { header: { crit: ['exp'] } }, error: InvalidRevocationListError },
    { name: 'alg none', options: { header: { alg: 'none' } }, error: InvalidRevocationListError },
    { name: 'alg HS256', options: { header: { alg: 'HS256' } }, error: InvalidRevocationListError },
    // Names inherited from Object.prototype must not pass the allowlist.
    { name: 'alg constructor', options: { header: { alg: 'constructor' } }, error: InvalidRevocationListError },
    { name: 'alg __proto__', options: { header: { alg: '__proto__' } }, error: InvalidRevocationListError },
    {
      name: 'an alg that is not a string',
      options: { header: { alg: { toString: 1 } } },
      error: InvalidRevocationListError,
    },
    { name: 'a header that is not an object', options: { rawHeader: null }, error: InvalidRevocationListError },
    { name: 'a payload that is not an object', options: { rawPayload: null }, error: InvalidRevocationListError },
    { name: 'no status_list', options: { payload: { status_list: undefined } }, error: InvalidRevocationListError },
    {
      name: 'an lst that is not deflate',
      options: { payload: { status_list: { bits: 1, lst: base64url.encode(new Uint8Array([1, 2, 3])) } } },
      error: InvalidRevocationListError,
    },
    { name: 'no x5c', options: { header: { x5c: undefined } }, error: UnableToExtractX5ChainFromJwtError },
    { name: 'an empty x5c', options: { header: { x5c: [] } }, error: UnableToExtractX5ChainFromJwtError },
    {
      name: 'an x5c that is not base64',
      options: { header: { x5c: ['!!!'] } },
      error: UnableToExtractX5ChainFromJwtError,
    },
  ])('Verify a JWT status list with $name', async ({ name, options, error }) => {
    const uri = await mockStatusList(`/broken-${name.replace(/ /g, '-')}`, { ...options, status: StatusType.Invalid })
    const verification = verify(uri)

    await expect(verification).rejects.toThrow(error)
    await expect(verification).rejects.not.toThrow(StatusListEntryNotValidError)
  })

  test('Verify a JWT status list signed by an untrusted certificate', async () => {
    const uri = await mockStatusList('/untrusted', { status: StatusType.Invalid })
    const verification = verify(uri, {
      trustedCertificates: [new Uint8Array(new X509Certificate(INVALID_CERTIFICATE).rawData)],
    })

    await expect(verification).rejects.toThrow('No trusted certificate was found while validating the X.509 chain')
    await expect(verification).rejects.not.toThrow(StatusListEntryNotValidError)
  })

  test('Request a CWT first, and verify it when the server serves both', async () => {
    const uri = 'https://example.org/negotiated'
    const statusListCwt = new StatusListCwt({
      payload: {
        statusList: new StatusList(new Array(10).fill(StatusType.Valid), 1),
        subject: uri,
        expirationTime: new Date(Date.now() + 3_600_000),
      },
      protectedHeaders: ProtectedHeaders.create({
        protectedHeaders: new Map<number, unknown>([
          [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
          [RegisteredCwtHeaderClaimKey.X5Chain, [certificate]],
        ]),
      }),
    })
    const cwt = await statusListCwt.signAndEncode(
      { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
      { sign: mdocContext.cose.sign1.sign }
    )

    let accept: string | null = null
    server.use(
      http.get(uri, ({ request }) => {
        accept = request.headers.get('Accept')
        return accept?.startsWith(MediaTypes.StatusListCwt)
          ? new HttpResponse(new Uint8Array(cwt), { headers: { 'Content-Type': MediaTypes.StatusListCwt } })
          : new HttpResponse('not.a.jwt', { headers: { 'Content-Type': MediaTypes.StatusListJwt } })
      })
    )

    const result = await verify(uri)

    expect(accept).toBe(`${MediaTypes.StatusListCwt},${MediaTypes.StatusListJwt};q=0.9`)
    expect(result.statusListCwt).toBeDefined()
    expect(result.statusListJwt).toBeUndefined()
  })
})
