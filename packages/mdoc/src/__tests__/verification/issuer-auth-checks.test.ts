import 'reflect-metadata'
import nodeCrypto from 'node:crypto'
import { DataItem, HashAlgorithm } from '@owf/cose'
import { hex } from '@owf/identity-common'
import * as x509 from '@peculiar/x509'
import { describe, expect, test } from 'vitest'
import {
  CoseKey,
  cborDecode,
  cborEncode,
  DeviceKey,
  Holder,
  Issuer,
  IssuerAuth,
  IssuerSigned,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  SignatureAlgorithm,
  type VerificationAssessment,
} from '../..'
import { DEVICE_JWK_PUBLIC, ISSUER_PRIVATE_KEY_JWK } from '../config'
import { mdocContext } from '../context'
import { createIssuerSigned, issuerCertificate, mdlDocType, mdlNamespace } from '../iso-mdoc-dc-api/fixtures'

x509.cryptoProvider.set(nodeCrypto.webcrypto as unknown as Crypto)

const countryCheck =
  "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate"
const jurisdictionCheck =
  "The 'issuing_jurisdiction' if present must match the 'stateOrProvinceName' in the subject field within the DS certificate"

const x5tCheck = 'The x5t in the protected header, if present, must be SHA-256 and match the issuer certificate'

const generateKeys = async () =>
  (await nodeCrypto.webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as unknown as CryptoKeyPair

/**
 * An IACA certificate and a document signer certificate it issued, with the given distinguished names.
 */
async function createDocumentSignerCertificate(options: { iacaName: string; documentSignerName: string }) {
  const iacaKeys = await generateKeys()
  const documentSignerKeys = await generateKeys()
  const notBefore = new Date(Date.now() - 60 * 60 * 1000)
  const notAfter = new Date(Date.now() + 60 * 60 * 1000)

  const iacaCertificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: options.iacaName,
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys: iacaKeys,
    extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
  })

  const documentSignerCertificate = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    issuer: iacaCertificate.subject,
    subject: options.documentSignerName,
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey: documentSignerKeys.publicKey,
    signingKey: iacaKeys.privateKey,
  })

  const { kty, crv, x, y, d } = (await nodeCrypto.webcrypto.subtle.exportKey(
    'jwk',
    documentSignerKeys.privateKey
  )) as Record<string, unknown>

  return {
    iacaCertificate: new Uint8Array(iacaCertificate.rawData),
    documentSignerCertificate: new Uint8Array(documentSignerCertificate.rawData),
    signingKey: CoseKey.fromJwk({ kty, crv, x, y, d, alg: 'ES256' }),
  }
}

async function collectIssuerChecks(options: {
  iacaName: string
  documentSignerName: string
  claims: Record<string, unknown>
}) {
  const { iacaCertificate, documentSignerCertificate, signingKey } = await createDocumentSignerCertificate(options)

  const issuer = new Issuer(mdlDocType, mdocContext)
  issuer.addIssuerNamespace(mdlNamespace, { family_name: 'Doe', ...options.claims })

  const signed = new Date(Date.now() - 60_000)
  const issuerSigned = await issuer.sign({
    signingKey,
    certificates: [documentSignerCertificate],
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
    validityInfo: { signed, validFrom: signed, validUntil: new Date(Date.now() + 60 * 60 * 1000) },
  })

  const checks: Array<VerificationAssessment> = []
  await Holder.verifyIssuerSigned(
    {
      issuerSigned,
      trustedCertificates: [{ issuance: [iacaCertificate] }],
      verificationCallback: (check) => checks.push(check),
    },
    mdocContext
  )

  return checks
}

describe('issuer auth checks', () => {
  test('disabling certificate chain validation verifies with the default callback', async () => {
    await expect(
      Holder.verifyIssuerSigned(
        { issuerSigned: await createIssuerSigned(), disableCertificateChainValidation: true },
        mdocContext
      )
    ).resolves.toBeDefined()
  })

  test('the MSO validity check reports the validity period it compared against', async () => {
    const issuerSigned = await createIssuerSigned()
    const { validFrom, validUntil } = issuerSigned.issuerAuth.mobileSecurityObject.validityInfo
    const now = new Date(validUntil.getTime() + 60 * 60 * 1000)

    const checks: Array<VerificationAssessment> = []
    await Holder.verifyIssuerSigned(
      {
        issuerSigned,
        disableCertificateChainValidation: true,
        now,
        skewSeconds: 30,
        verificationCallback: (check) => checks.push(check),
      },
      mdocContext
    )

    expect(checks.find((check) => check.check === 'The MSO must be valid at the time of verification')).toMatchObject({
      status: 'FAILED',
      reason: `The MSO must be valid at the time of verification (${now.toUTCString()}); its validity period is ${validFrom.toUTCString()} to ${validUntil.toUTCString()} (allowed clock skew 30s)`,
    })
  })

  test('an MSO with a null status verifies as signed', async () => {
    const { issuerAuth, issuerNamespaces } = await createIssuerSigned()
    const mobileSecurityObject = cborDecode<Map<string, unknown>>(issuerAuth.mobileSecurityObject.encode())
    const issuerSignedBytes = IssuerSigned.create({
      issuerNamespaces,
      issuerAuth: await IssuerAuth.create({
        protectedHeaders: issuerAuth.protectedHeaders,
        unprotectedHeaders: issuerAuth.unprotectedHeaders,
        payload: cborEncode(DataItem.fromData(mobileSecurityObject.set('status', null))),
      }).sign(
        { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
        mdocContext.cose.sign1
      ),
    }).encode()

    const issuerSigned = IssuerSigned.decode(issuerSignedBytes)
    expect(issuerSigned.issuerAuth.mobileSecurityObject.status).toBeUndefined()
    await expect(
      Holder.verifyIssuerSigned({ issuerSigned, trustedCertificates: [{ issuance: [issuerCertificate] }] }, mdocContext)
    ).resolves.toBeDefined()

    // Forwarding the decoded issuer signed keeps the null the issuer signed.
    expect(hex.encode(issuerSigned.encode())).toBe(hex.encode(issuerSignedBytes))
  })

  describe('x5t (18013-5 second edition 12.3.4)', () => {
    /** The x5t check of an issuer signed whose protected header carries `x5t`. */
    async function x5tCheckFor(x5t?: (certificate: Uint8Array) => Promise<unknown>) {
      const { issuerAuth, issuerNamespaces } = await createIssuerSigned()
      const issuerSigned = IssuerSigned.create({
        issuerNamespaces,
        issuerAuth: await IssuerAuth.create({
          protectedHeaders: ProtectedHeaders.create({
            protectedHeaders: new Map<number, unknown>([
              [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
              ...(x5t
                ? [[RegisteredCwtHeaderClaimKey.X5T, await x5t(issuerAuth.certificate)] as [number, unknown]]
                : []),
            ]),
          }),
          unprotectedHeaders: issuerAuth.unprotectedHeaders,
          payload: issuerAuth.payload,
        }).sign(
          { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
          mdocContext.cose.sign1
        ),
      })

      const checks: Array<VerificationAssessment> = []
      await Holder.verifyIssuerSigned(
        {
          issuerSigned,
          trustedCertificates: [{ issuance: [issuerCertificate] }],
          verificationCallback: (check) => checks.push(check),
        },
        mdocContext
      )

      return checks.find((check) => check.check === x5tCheck)
    }

    const sha256 = (bytes: Uint8Array) => mdocContext.crypto.digest({ digestAlgorithm: 'SHA-256', bytes })

    test('passes without an x5t, as the first edition has none', async () => {
      expect(await x5tCheckFor()).toMatchObject({ status: 'PASSED' })
    })

    test('passes with a SHA-256 x5t of the issuer certificate', async () => {
      expect(await x5tCheckFor(async (certificate) => [HashAlgorithm.SHA256, await sha256(certificate)])).toMatchObject(
        {
          status: 'PASSED',
        }
      )
    })

    test('includeX5t adds a SHA-256 x5t of the issuer certificate that verifies', async () => {
      const issuer = new Issuer(mdlDocType, mdocContext)
      issuer.addIssuerNamespace(mdlNamespace, { family_name: 'Doe' })
      const signed = new Date(Date.now() - 60_000)
      const issuerSigned = await issuer.sign({
        signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
        certificates: [issuerCertificate],
        algorithm: SignatureAlgorithm.ES256,
        digestAlgorithm: 'SHA-256',
        deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
        validityInfo: { signed, validFrom: signed, validUntil: new Date(Date.now() + 60 * 60 * 1000) },
        includeX5t: true,
      })

      expect(issuerSigned.issuerAuth.protectedHeaders.headers.get(RegisteredCwtHeaderClaimKey.X5T)).toEqual([
        HashAlgorithm.SHA256,
        await sha256(issuerCertificate),
      ])

      const checks: Array<VerificationAssessment> = []
      await Holder.verifyIssuerSigned(
        {
          issuerSigned: IssuerSigned.decode(issuerSigned.encode()),
          trustedCertificates: [{ issuance: [issuerCertificate] }],
          verificationCallback: (check) => checks.push(check),
        },
        mdocContext
      )
      expect(checks.find((check) => check.check === x5tCheck)?.status).toBe('PASSED')
    })

    test('fails with an x5t that is not SHA-256', async () => {
      // SHA-512 (-44)
      expect(await x5tCheckFor(async (certificate) => [-44, await sha256(certificate)])).toMatchObject({
        status: 'FAILED',
        reason: "The x5t of the protected header uses hash algorithm '-44', only SHA-256 (-16) is supported",
      })
    })

    test('fails with an x5t of another certificate', async () => {
      expect(await x5tCheckFor(async () => [HashAlgorithm.SHA256, await sha256(new Uint8Array([1]))])).toMatchObject({
        status: 'FAILED',
        reason: 'The x5t of the protected header does not match the leaf of the x5chain',
      })
    })

    test('fails with a malformed x5t', async () => {
      expect(await x5tCheckFor(async () => [HashAlgorithm.SHA256])).toMatchObject({
        status: 'FAILED',
        reason: 'The x5t of the protected header is not a valid COSE_CertHash',
      })
    })
  })

  test('issuing_country is checked against the subject of the DS certificate, not its issuer', async () => {
    const checks = await collectIssuerChecks({
      iacaName: 'CN=IACA, C=NL',
      documentSignerName: 'CN=DS, C=US',
      claims: { issuing_country: 'US' },
    })

    expect(checks.filter((check) => check.status === 'FAILED')).toStrictEqual([])
    expect(checks.find((check) => check.check === countryCheck)?.status).toBe('PASSED')
  })

  test('issuing_jurisdiction is not checked when the DS certificate has no stateOrProvinceName (7.2.1)', async () => {
    const checks = await collectIssuerChecks({
      iacaName: 'CN=IACA, C=US',
      documentSignerName: 'CN=DS, C=US',
      claims: { issuing_country: 'US', issuing_jurisdiction: 'US-NY' },
    })

    expect(checks.find((check) => check.check === jurisdictionCheck)?.status).toBe('PASSED')
  })

  test('issuing_jurisdiction must match the stateOrProvinceName of the DS certificate when present', async () => {
    const checks = await collectIssuerChecks({
      iacaName: 'CN=IACA, C=US',
      documentSignerName: 'CN=DS, C=US, ST=US-CA',
      claims: { issuing_country: 'US', issuing_jurisdiction: 'US-NY' },
    })

    expect(checks.find((check) => check.check === jurisdictionCheck)?.status).toBe('FAILED')
  })
})
