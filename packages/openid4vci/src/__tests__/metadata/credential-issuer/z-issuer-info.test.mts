import { describe, expect, test } from 'vitest'
import { type IssuerInfo, type IssuerInfoEntry, zCredentialIssuerMetadataSchema, zIssuerInfo } from '../../../index'

const registrationCertificate: IssuerInfoEntry = {
  format: 'registration_cert',
  data: 'registration.certificate.jwt',
}
const issuerInfo: IssuerInfo = [
  registrationCertificate,
  {
    format: 'custom',
    data: { issuer: 'Example Issuer', attributes: { roles: ['issuer'] } },
    credential_ids: ['credential-query-id'],
  },
]
const credentialIssuerMetadata = {
  credential_issuer: 'https://credential-issuer.com',
  credential_endpoint: 'https://credential-issuer.com/credential',
  credential_configurations_supported: {},
}

describe('Issuer Info', () => {
  test('preserves opaque attestation data and optional credential identifiers', () => {
    expect(zIssuerInfo.parse(issuerInfo)).toStrictEqual(issuerInfo)
    expect(
      zCredentialIssuerMetadataSchema.parse({
        ...credentialIssuerMetadata,
        issuer_info: issuerInfo,
      }).issuer_info
    ).toStrictEqual(issuerInfo)
  })

  test('issuer info is optional in credential issuer metadata', () => {
    expect(zCredentialIssuerMetadataSchema.parse(credentialIssuerMetadata)).toStrictEqual(credentialIssuerMetadata)
  })

  test.each([
    { description: 'empty array', issuer_info: [] },
    { description: 'null', issuer_info: null },
    { description: 'missing format', issuer_info: [{ data: 'attestation' }] },
    { description: 'missing data', issuer_info: [{ format: 'custom' }] },
    { description: 'numeric format', issuer_info: [{ format: 1, data: 'attestation' }] },
    { description: 'numeric data', issuer_info: [{ format: 'custom', data: 1 }] },
    { description: 'null data', issuer_info: [{ format: 'custom', data: null }] },
    { description: 'array data', issuer_info: [{ format: 'custom', data: [] }] },
    {
      description: 'empty credential identifiers',
      issuer_info: [{ format: 'custom', data: {}, credential_ids: [] }],
    },
    {
      description: 'numeric credential identifiers',
      issuer_info: [{ format: 'custom', data: {}, credential_ids: [1] }],
    },
  ])('rejects $description', ({ issuer_info }) => {
    expect(zIssuerInfo.safeParse(issuer_info).success).toBe(false)
    expect(zCredentialIssuerMetadataSchema.safeParse({ ...credentialIssuerMetadata, issuer_info }).success).toBe(false)
  })
})
