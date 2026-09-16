import 'reflect-metadata'
import { RegisteredCwtHeaderClaimKey } from '@owf/cose'
import { X509Certificate } from '@peculiar/x509'
import { describe, expect, test } from 'vitest'
import {
  CoseKey,
  DateOnly,
  DeviceKey,
  DuplicateElementIdentifierError,
  InvalidValidityInfoError,
  IssuerSigned,
  MdlError,
  SignatureAlgorithm,
  SignatureAlgorithmDoesNotMatchSigningKeyAlgorithmError,
} from '../..'
import { IssuerSignedBuilder } from '../../mdoc/builders/issuer-signed-builder'
import { DEVICE_JWK_PUBLIC, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK } from '../config'
import { mdocContext } from '../context'

const claims = {
  family_name: 'Jones',
  given_name: 'Ava',
  birth_date: new DateOnly('2007-03-25'),
  issue_date: new Date('2023-09-01'),
  expiry_date: new Date('2028-09-30'),
  issuing_country: 'US',
  issuing_authority: 'NY DMV',
  document_number: '01-856-5050',
  portrait: 'bstr',
  driving_privileges: [
    {
      vehicle_category_code: 'A',
      issue_date: new DateOnly('2021-09-02'),
      expiry_date: new DateOnly('2026-09-20'),
    },
    {
      vehicle_category_code: 'B',
      issue_date: new DateOnly('2022-09-02'),
      expiry_date: new DateOnly('2027-09-20'),
    },
  ],
}

describe('issuer signed builder', () => {
  let issuerSigned: IssuerSigned

  const signed = new Date('2023-10-24T14:55:18Z')
  const validFrom = new Date(signed)
  validFrom.setMinutes(signed.getMinutes() + 5)
  const validUntil = new Date(signed)
  validUntil.setFullYear(signed.getFullYear() + 30)

  test('correctly instantiate an issuer signed object', async () => {
    const issuerSignedBuilder = new IssuerSignedBuilder('org.iso.18013.5.1.mDL', mdocContext).addIssuerNamespace(
      'org.iso.18013.5.1',
      claims
    )

    const coseKey = CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK)
    expect(coseKey.jwk).toMatchObject(ISSUER_PRIVATE_KEY_JWK)

    issuerSigned = await issuerSignedBuilder.sign({
      signingKey: coseKey,
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
    })

    expect(issuerSigned.issuerNamespaces).toBeDefined()
    expect(issuerSigned.issuerNamespaces?.issuerNamespaces.has('org.iso.18013.5.1')).toBeTruthy()
    expect(issuerSigned.issuerAuth.signature).toBeDefined()

    const verificationResult = await issuerSigned.issuerAuth.verifySignature(
      {
        key: await mdocContext.x509.getPublicKey({
          certificate: issuerSigned.issuerAuth.certificate,
          algorithm: SignatureAlgorithm.ES256,
        }),
      },
      { verify: mdocContext.cose.sign1.verify }
    )

    expect(verificationResult).toBeTruthy()
  })

  test('verify issuer signature', async () => {
    await expect(
      issuerSigned.issuerAuth.verify(
        {
          trustedCertificates: [{ issuance: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)] }],
        },
        mdocContext
      )
    ).resolves.not.toThrow()
  })

  test('Signature algorithm and key algorithm do not match', async () => {
    const issuerSignedBuilder = new IssuerSignedBuilder('org.iso.18013.5.1.mDL', mdocContext).addIssuerNamespace(
      'org.iso.18013.5.1',
      claims
    )

    const coseKey = CoseKey.fromJwk({ ...ISSUER_PRIVATE_KEY_JWK, alg: 'ES256' })
    expect(coseKey.jwk).toMatchObject(ISSUER_PRIVATE_KEY_JWK)

    await expect(
      issuerSignedBuilder.sign({
        signingKey: coseKey,
        certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        algorithm: SignatureAlgorithm.ES512,
        digestAlgorithm: 'SHA-256',
        deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
        validityInfo: { signed, validFrom, validUntil },
      })
    ).rejects.toThrow(SignatureAlgorithmDoesNotMatchSigningKeyAlgorithmError)
  })

  test('verify validity info', async () => {
    const { validityInfo } = issuerSigned.issuerAuth.mobileSecurityObject

    expect(validityInfo).toBeDefined()
    expect(validityInfo.signed).toEqual(signed)
    expect(validityInfo.validFrom).toEqual(validFrom)
    expect(validityInfo.validUntil).toEqual(validUntil)
    expect(validityInfo.expectedUpdate).toBeUndefined()
  })

  test('set correct digest algorithm', () => {
    const { digestAlgorithm } = issuerSigned.issuerAuth.mobileSecurityObject
    expect(digestAlgorithm).toEqual('SHA-256')
  })

  test('set correct device key', () => {
    const { deviceKeyInfo } = issuerSigned.issuerAuth.mobileSecurityObject
    expect(deviceKeyInfo?.deviceKey).toBeDefined()
    expect(deviceKeyInfo.deviceKey.jwk).toEqual(DEVICE_JWK_PUBLIC)
  })

  test('should include the namespace and attributes', () => {
    const prettyClaims = issuerSigned.getPrettyClaims('org.iso.18013.5.1')
    expect(prettyClaims).toEqual(claims)
  })

  test('should support certificate chain with multiple certificates', async () => {
    const issuerSignedBuilder = new IssuerSignedBuilder('org.iso.18013.5.1.mDL', mdocContext).addIssuerNamespace(
      'org.iso.18013.5.1',
      { family_name: 'Smith' }
    )

    const cert1 = new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)
    const cert2 = new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)

    const issuerSignedWithChain = await issuerSignedBuilder.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [cert1, cert2],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
    })

    expect(issuerSignedWithChain.issuerAuth.certificateChain).toHaveLength(2)
    expect(issuerSignedWithChain.issuerAuth.certificateChain[0]).toEqual(cert1)
    expect(issuerSignedWithChain.issuerAuth.certificateChain[1]).toEqual(cert2)

    // Verify that the certificate chain can be decoded correctly
    const encodedChain = issuerSignedWithChain.encode()
    const decodedChain = IssuerSigned.decode(encodedChain)
    expect(decodedChain.issuerAuth.certificateChain).toHaveLength(2)
  })

  const certificate = new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)
  const signOptions = {
    signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
    certificates: [certificate],
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256' as const,
    deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
  }

  test('a single certificate is encoded as a byte string in the x5chain header (RFC 9360)', async () => {
    const issuerSigned = await new IssuerSignedBuilder('org.iso.18013.5.1.mDL', mdocContext)
      .addIssuerNamespace('org.iso.18013.5.1', { family_name: 'Smith' })
      .sign({ ...signOptions, validityInfo: { signed, validFrom, validUntil } })

    const x5chain = issuerSigned.issuerAuth.unprotectedHeaders.headers?.get(RegisteredCwtHeaderClaimKey.X5Chain)
    expect(x5chain).toBeInstanceOf(Uint8Array)
    expect(IssuerSigned.decode(issuerSigned.encode()).issuerAuth.certificateChain).toEqual([certificate])
  })

  test.each([
    ['validFrom is before signed', { signed, validFrom: new Date(signed.getTime() - 1000), validUntil }],
    ['validUntil is validFrom', { signed, validFrom, validUntil: validFrom }],
    ['validUntil is before validFrom', { signed, validFrom, validUntil: new Date(validFrom.getTime() - 1000) }],
  ])('signing throws when %s (9.1.2.4)', async (_, validityInfo) => {
    const issuerSignedBuilder = new IssuerSignedBuilder('org.iso.18013.5.1.mDL', mdocContext).addIssuerNamespace(
      'org.iso.18013.5.1',
      { family_name: 'Smith' }
    )

    await expect(issuerSignedBuilder.sign({ ...signOptions, validityInfo })).rejects.toThrow(InvalidValidityInfoError)
  })

  test('validFrom may be signed', async () => {
    const issuerSignedBuilder = new IssuerSignedBuilder('org.iso.18013.5.1.mDL', mdocContext).addIssuerNamespace(
      'org.iso.18013.5.1',
      { family_name: 'Smith' }
    )

    await expect(
      issuerSignedBuilder.sign({ ...signOptions, validityInfo: { signed, validFrom: signed, validUntil } })
    ).resolves.toBeInstanceOf(IssuerSigned)
  })

  test('adding an element identifier twice to a namespace throws', () => {
    const issuerSignedBuilder = new IssuerSignedBuilder('org.iso.18013.5.1.mDL', mdocContext).addIssuerNamespace(
      'org.iso.18013.5.1',
      { family_name: 'Smith' }
    )

    expect(() => issuerSignedBuilder.addIssuerNamespace('org.iso.18013.5.1', { family_name: 'Jones' })).toThrow(
      DuplicateElementIdentifierError
    )
    // The same element identifier in another namespace is a different element.
    expect(() => issuerSignedBuilder.addIssuerNamespace('org.example', { family_name: 'Jones' })).not.toThrow()
  })

  test('adding elements that throw leaves the namespace unchanged', async () => {
    const issuerSignedBuilder = new IssuerSignedBuilder('org.iso.18013.5.1.mDL', mdocContext).addIssuerNamespace(
      'org.iso.18013.5.1',
      { family_name: 'Smith' }
    )

    // `given_name` comes before the duplicate, so it would be added before the call throws.
    expect(() =>
      issuerSignedBuilder.addIssuerNamespace('org.iso.18013.5.1', { given_name: 'Ava', family_name: 'Jones' })
    ).toThrow(DuplicateElementIdentifierError)
    expect(() => issuerSignedBuilder.addIssuerNamespace('org.iso.18013.5.1', { given_name: 'Ava' })).not.toThrow()

    const issuerSigned = await issuerSignedBuilder.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
    })
    expect(
      issuerSigned.issuerNamespaces?.issuerNamespaces.get('org.iso.18013.5.1')?.map((item) => item.elementIdentifier)
    ).toEqual(['family_name', 'given_name'])
  })

  test('adding an element throws when the generated digest ID is already used in the namespace', () => {
    const constantContext = {
      ...mdocContext,
      crypto: { ...mdocContext.crypto, random: (length: number) => new Uint8Array(length) },
    }

    expect(() =>
      new IssuerSignedBuilder('org.iso.18013.5.1.mDL', constantContext).addIssuerNamespace('org.iso.18013.5.1', {
        a: 1,
        b: 2,
      })
    ).toThrow(MdlError)
  })
})
