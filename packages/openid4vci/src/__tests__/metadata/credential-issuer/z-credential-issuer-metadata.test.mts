import { describe, expect, test } from 'vitest'
import type { $ZodIssueInvalidUnion } from 'zod/v4/core'
import {
  zCredentialConfigurationSupportedWithFormats,
  zCredentialIssuerMetadata,
  zCredentialIssuerMetadataDraft11ToV1,
  zCredentialIssuerMetadataWithDraftVersion,
} from '../../../metadata/credential-issuer/z-credential-issuer-metadata'
import { Openid4vciVersion } from '../../../version'
import { paradymDraft13 } from '../../__fixtures__/paradym'

describe('Credential Issuer Metadata', () => {
  test('should parse credential configurations supported with format', () => {
    // Correct: sd-jwt with vct
    expect(
      zCredentialConfigurationSupportedWithFormats.safeParse({
        format: 'vc+sd-jwt',
        // vct should be required if format is vc+sd-jwt
        vct: 'SD_JWT_VC_example_in_OpenID4VCI',
      })
    ).toStrictEqual({
      data: expect.objectContaining({}),
      success: true,
    })

    const parseResult = zCredentialConfigurationSupportedWithFormats.safeParse({
      format: 'vc+sd-jwt',
      // vct should be required if format is vc+sd-jwt
      // vct: 'SD_JWT_VC_example_in_OpenID4VCI',
    })

    // Incorrect: sd-jwt without vct
    expect(parseResult.success).toBe(false)
    expect((parseResult.error?.issues[0] as $ZodIssueInvalidUnion)?.errors[0][0]).toEqual({
      code: 'invalid_type',
      // FIXME(vc+sd-jwt): fix expected to be 'string' when dropping support for legacy vc+sd-jwt format.
      expected: 'object',
      path: ['credential_definition'],
      message: 'expected object, received undefined',
    })

    // Correct: mso mdoc with doctype
    expect(
      zCredentialConfigurationSupportedWithFormats.safeParse({
        format: 'mso_mdoc',
        // doctype should be required if format is mso_mdoc
        doctype: 'org.iso.18013.5.1.mDL',
      })
    ).toStrictEqual({
      data: expect.objectContaining({}),
      success: true,
    })

    // Incorrect: mso mdoc without doctype
    const parseResultMdoc = zCredentialConfigurationSupportedWithFormats.safeParse({
      format: 'mso_mdoc',
      // doctype should be required if format is mso_mdoc
      // doctype: 'org.iso.18013.5.1.mDL',
    })
    expect(parseResultMdoc.success).toEqual(false)
    expect(parseResultMdoc.error?.issues[0]).toMatchObject({
      code: 'invalid_union',
      message: 'Invalid input',
      path: [],
    })

    expect((parseResultMdoc.error?.issues[0] as $ZodIssueInvalidUnion | undefined)?.errors[0]).toMatchObject([
      {
        code: 'invalid_type',
        expected: 'string',
        path: ['doctype'],
        message: 'expected string, received undefined',
      },
    ])
  })

  test('parse draft 13 credential issuer metadata', () => {
    const parseResult = zCredentialIssuerMetadata.safeParse(paradymDraft13.credentialIssuerMetadata)
    expect(parseResult).toStrictEqual({
      data: paradymDraft13.credentialIssuerMetadata,
      success: true,
    })
  })

  test('parse draft 11 credential issuer metadata', () => {
    const credentials_supported = [
      {
        format: 'vc+sd-jwt',
        vct: 'vct-test-no-id-should-be-removed',
      },
      {
        id: 'sd-jwt',
        format: 'vc+sd-jwt',
        vct: 'vct-test-id',
        display: [
          {
            name: 'hello',
            logo: {
              // should become ur
              url: 'https://logo.com',
            },
            // Should be removed (as now uri is required)
            background_image: {},
          },
        ],
      },
      {
        id: 'w3c-jwt-vc-json',
        format: 'jwt_vc_json',
        types: ['one'],
        extra_property: 'should_stay',
        credentialSubject: {
          name: {
            mandatory: true,
          },
        },
      },
      {
        id: 'w3c-jwt-vc-json-ld',
        format: 'jwt_vc_json-ld',
        types: ['one'],
        '@context': ['two'],
        credentialSubject: {
          name: {
            mandatory: true,
          },
        },
      },
      {
        id: 'w3c-ldp-vc',
        format: 'ldp_vc',
        types: ['one'],
        '@context': ['two'],
        credentialSubject: {
          name: {
            mandatory: true,
          },
        },
        cryptographic_suites_supported: ['EdDSA', 'ES256'],
      },
      {
        id: 'mso-mdoc',
        format: 'mso_mdoc',
        doctype: 'some.doc.type',
        cryptographic_suites_supported: ['EdDSA', 'ES256'],
      },
    ]

    const credential_configurations_supported = {
      'sd-jwt': {
        format: 'dc+sd-jwt',
        vct: 'vct-test-id',
        credential_metadata: {
          display: [
            {
              name: 'hello',
              logo: {
                uri: 'https://logo.com',
              },
            },
          ],
        },
      },
      'w3c-jwt-vc-json': {
        format: 'jwt_vc_json',
        extra_property: 'should_stay',
        credential_definition: {
          type: ['one'],
          credentialSubject: {
            name: {
              mandatory: true,
            },
          },
        },
      },
      'w3c-jwt-vc-json-ld': {
        format: 'jwt_vc_json-ld',
        credential_definition: {
          type: ['one'],
          '@context': ['two'],
          credentialSubject: {
            name: {
              mandatory: true,
            },
          },
        },
      },
      'w3c-ldp-vc': {
        format: 'ldp_vc',
        credential_definition: {
          type: ['one'],
          '@context': ['two'],
          credentialSubject: {
            name: {
              mandatory: true,
            },
          },
        },
        credential_signing_alg_values_supported: ['EdDSA', 'ES256'],
      },
      'mso-mdoc': {
        format: 'mso_mdoc',
        doctype: 'some.doc.type',
        // For mso_mdoc, JOSE algorithms are transformed to COSE numbers
        // EdDSA -> -19 (Ed25519), ES256 -> -9 (ESP256)
        credential_signing_alg_values_supported: [-19, -9],
      },
    }

    const parseResult = zCredentialIssuerMetadataDraft11ToV1.safeParse({
      credential_endpoint: 'https://credential-issuer.com/credential',
      credential_issuer: 'https://credential-issuer.com',
      credentials_supported,
      authorization_server: 'https://test.auth.com',
    })
    expect(parseResult).toStrictEqual({
      data: {
        credential_endpoint: 'https://credential-issuer.com/credential',
        credential_issuer: 'https://credential-issuer.com',
        credential_configurations_supported,
        authorization_servers: ['https://test.auth.com'],
      },
      success: true,
    })
  })

  test('parses credential request encryption metadata', () => {
    const credentialRequestEncryption = {
      jwks: {
        custom: 'preserved',
        keys: [{ kty: 'EC', kid: 'request-key', alg: 'ECDH-ES', crv: 'P-256', x: 'x', y: 'y' }],
      },
      enc_values_supported: ['A128GCM'],
      encryption_required: false,
    }
    const metadata = {
      credential_issuer: 'https://credential-issuer.com',
      credential_endpoint: 'https://credential-issuer.com/credential',
      credential_configurations_supported: {},
      credential_request_encryption: credentialRequestEncryption,
    }

    expect(zCredentialIssuerMetadata.safeParse(metadata)).toMatchObject({
      success: true,
      data: { credential_request_encryption: credentialRequestEncryption },
    })
    expect(zCredentialIssuerMetadataWithDraftVersion.safeParse(metadata)).toMatchObject({
      success: true,
      data: { originalDraftVersion: Openid4vciVersion.V1 },
    })
  })

  test('credential request encryption takes precedence over Draft 15 indicators', () => {
    const metadata = {
      credential_issuer: 'https://credential-issuer.com',
      credential_endpoint: 'https://credential-issuer.com/credential',
      credential_configurations_supported: {
        pid: {
          format: 'dc+sd-jwt',
          vct: 'https://credential-issuer.com/pid',
        },
      },
    }

    expect(zCredentialIssuerMetadataWithDraftVersion.safeParse(metadata)).toMatchObject({
      success: true,
      data: { originalDraftVersion: Openid4vciVersion.Draft15 },
    })

    expect(
      zCredentialIssuerMetadataWithDraftVersion.safeParse({
        ...metadata,
        credential_request_encryption: {
          jwks: {
            keys: [{ kty: 'EC', kid: 'request-key', alg: 'ECDH-ES', crv: 'P-256', x: 'x', y: 'y' }],
          },
          enc_values_supported: ['A128GCM'],
          encryption_required: false,
        },
      })
    ).toMatchObject({
      success: true,
      data: { originalDraftVersion: Openid4vciVersion.V1 },
    })
  })

  test('does not parse credential request encryption metadata as Draft 11', () => {
    expect(
      zCredentialIssuerMetadataDraft11ToV1.safeParse({
        credential_endpoint: 'https://credential-issuer.com/credential',
        credential_issuer: 'https://credential-issuer.com',
        credentials_supported: [],
        credential_request_encryption: {
          jwks: {
            keys: [{ kty: 'EC', kid: 'request-key', alg: 'ECDH-ES', crv: 'P-256', x: 'x', y: 'y' }],
          },
          enc_values_supported: ['A128GCM'],
          encryption_required: false,
        },
      }).success
    ).toBe(false)
  })

  test.each([
    ['missing jwks', { enc_values_supported: ['A128GCM'], encryption_required: false }],
    ['empty keys', { jwks: { keys: [] }, enc_values_supported: ['A128GCM'], encryption_required: false }],
    [
      'a key with alg none',
      {
        jwks: { keys: [{ kty: 'EC', kid: 'request-key', alg: 'none' }] },
        enc_values_supported: ['A128GCM'],
        encryption_required: false,
      },
    ],
    [
      'a key with empty alg',
      {
        jwks: { keys: [{ kty: 'EC', kid: 'request-key', alg: '' }] },
        enc_values_supported: ['A128GCM'],
        encryption_required: false,
      },
    ],
    [
      'a key without kid',
      {
        jwks: { keys: [{ kty: 'EC', alg: 'ECDH-ES' }] },
        enc_values_supported: ['A128GCM'],
        encryption_required: false,
      },
    ],
    [
      'a key without alg',
      {
        jwks: { keys: [{ kty: 'EC', kid: 'request-key' }] },
        enc_values_supported: ['A128GCM'],
        encryption_required: false,
      },
    ],
    [
      'duplicate kid values',
      {
        jwks: {
          keys: [
            { kty: 'EC', kid: 'request-key', alg: 'ECDH-ES' },
            { kty: 'EC', kid: 'request-key', alg: 'ECDH-ES' },
          ],
        },
        enc_values_supported: ['A128GCM'],
        encryption_required: false,
      },
    ],
    [
      'empty enc_values_supported',
      {
        jwks: { keys: [{ kty: 'EC', kid: 'request-key', alg: 'ECDH-ES' }] },
        enc_values_supported: [],
        encryption_required: false,
      },
    ],
    [
      'missing encryption_required',
      { jwks: { keys: [{ kty: 'EC', kid: 'request-key', alg: 'ECDH-ES' }] }, enc_values_supported: ['A128GCM'] },
    ],
  ])('rejects invalid credential request encryption metadata: %s', (_description, credentialRequestEncryption) => {
    expect(
      zCredentialIssuerMetadata.safeParse({
        credential_issuer: 'https://credential-issuer.com',
        credential_endpoint: 'https://credential-issuer.com/credential',
        credential_configurations_supported: {},
        credential_request_encryption: credentialRequestEncryption,
      }).success
    ).toBe(false)
  })
})
