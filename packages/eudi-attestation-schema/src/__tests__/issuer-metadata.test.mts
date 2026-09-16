import { describe, expect, it } from 'vitest'
import { schemaMeta, schemaURI } from '../builders'
import { buildCredentialConfigurationTemplate, validateIssuerMetadataAgainstProfile } from '../issuer-metadata'
import type { IssuanceProfile, ResolvedSchemaReference } from '../types'

const RULEBOOK_INTEGRITY = 'sha256-cJe/IG7DijmXd2FpecyWJVnZ9EuKKprly5auxGm1uIw='
const SCHEMA_INTEGRITY = 'sha256-M8H+reBt9Nr/s8CRicJrthAnk7UdWyTyONW0N8Z/Axw='
const VCT = 'eu.europa.ec.eudi.pid.1'

const PROFILE: IssuanceProfile = {
  credentialSigningAlgValuesSupported: ['ES256', 'ES384'],
  cryptographicBindingMethodsSupported: ['jwk'],
  proofTypesSupported: {
    jwt: { proof_signing_alg_values_supported: ['ES256'] },
  },
  keyAttestationRequired: true,
  statusMechanism: { type: 'token_status_list', required: true },
  maxValidityPeriod: 7776000,
  batchIssuanceAllowed: false,
}

function buildSchemaMeta(profile?: IssuanceProfile) {
  const builder = schemaMeta()
    .id('https://example.com/attestations/pid')
    .version('1.0.0')
    .rulebookURI('https://example.com/rulebook.md')
    .rulebookIntegrity(RULEBOOK_INTEGRITY)
    .attestationLoS('iso_18045_basic')
    .bindingType('key')
    .addSchemaURI(
      schemaURI()
        .format('dc+sd-jwt')
        .uri('https://example.com/sd-jwt.json')
        .integrity(SCHEMA_INTEGRITY)
        .meta({ vct: VCT })
        .build()
    )

  if (profile) {
    builder.issuanceProfile(profile)
  }

  return builder.build()
}

function conformantIssuerMetadata(): Record<string, unknown> {
  return {
    credential_issuer: 'https://issuer.example.com',
    credential_configurations_supported: {
      [VCT]: {
        format: 'dc+sd-jwt',
        vct: VCT,
        scope: 'pid',
        credential_signing_alg_values_supported: ['ES256'],
        cryptographic_binding_methods_supported: ['jwk'],
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ['ES256'],
            key_attestations_required: {},
          },
        },
      },
    },
  }
}

describe('issuanceProfile', () => {
  it('is optional', () => {
    expect(buildSchemaMeta().issuanceProfile).toBeUndefined()
  })

  it('is preserved when provided', () => {
    expect(buildSchemaMeta(PROFILE).issuanceProfile).toEqual(PROFILE)
  })

  it('rejects binding constraints when bindingType is none', () => {
    expect(() =>
      schemaMeta()
        .id('https://example.com/attestations/pid')
        .version('1.0.0')
        .rulebookURI('https://example.com/rulebook.md')
        .rulebookIntegrity(RULEBOOK_INTEGRITY)
        .attestationLoS('iso_18045_basic')
        .bindingType('none')
        .addSchemaURI(
          schemaURI()
            .format('dc+sd-jwt')
            .uri('https://example.com/sd-jwt.json')
            .integrity(SCHEMA_INTEGRITY)
            .meta({ vct: VCT })
            .build()
        )
        .issuanceProfile({ cryptographicBindingMethodsSupported: ['jwk'] })
        .build()
    ).toThrow(/cryptographicBindingMethodsSupported/)
  })
})

describe('buildCredentialConfigurationTemplate', () => {
  it('fills type-determined members and omits deployment members', () => {
    const template = buildCredentialConfigurationTemplate({
      schemaMeta: buildSchemaMeta(),
      format: 'dc+sd-jwt',
    })

    expect(template.credentialConfigurationId).toBe(VCT)
    expect(template.credentialConfiguration).toEqual({
      format: 'dc+sd-jwt',
      vct: VCT,
    })
    expect(template.deploymentFields.credentialConfiguration).toContain('scope')
    expect(template.deploymentFields.issuerMetadata).toContain('credential_endpoint')
  })

  it('maps the issuance profile onto OID4VCI members', () => {
    const template = buildCredentialConfigurationTemplate({
      schemaMeta: buildSchemaMeta(PROFILE),
      format: 'dc+sd-jwt',
    })

    expect(template.credentialConfiguration).toMatchObject({
      credential_signing_alg_values_supported: ['ES256', 'ES384'],
      cryptographic_binding_methods_supported: ['jwk'],
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: {},
        },
      },
    })
  })

  it('includes portable OID4VCI display and claim metadata in the template', () => {
    const metadata = schemaMeta()
      .id('https://example.com/attestations/pid')
      .version('1.0.0')
      .rulebookURI('https://example.com/rulebook.md')
      .rulebookIntegrity(RULEBOOK_INTEGRITY)
      .attestationLoS('iso_18045_basic')
      .bindingType('key')
      .addSchemaURI(
        schemaURI()
          .format('dc+sd-jwt')
          .uri('https://example.com/sd-jwt.json')
          .integrity(SCHEMA_INTEGRITY)
          .meta({ vct: VCT })
          .credentialMetadata({
            display: [{ name: 'Personal Identity Data', locale: 'en' }],
            claims: [
              {
                path: ['family_name'],
                display: [{ name: 'Family name', locale: 'en' }],
              },
            ],
          })
          .build()
      )
      .build()

    const template = buildCredentialConfigurationTemplate({
      schemaMeta: metadata,
      format: 'dc+sd-jwt',
    })

    expect(template.credentialConfiguration).toMatchObject({
      vct: VCT,
      display: [{ name: 'Personal Identity Data', locale: 'en' }],
      claims: [
        {
          path: ['family_name'],
          display: [{ name: 'Family name', locale: 'en' }],
        },
      ],
    })
  })

  it('derives claims from a resolved reference', () => {
    const resolvedReferences: ResolvedSchemaReference[] = [
      {
        format: 'dc+sd-jwt',
        uri: 'https://example.com/sd-jwt.json',
        integrity: SCHEMA_INTEGRITY,
        meta: { vct: VCT },
        rawSchema: {},
        parsedSchema: {
          type: 'object',
          properties: { given_name: { type: 'string' } },
        },
      },
    ]

    const template = buildCredentialConfigurationTemplate({
      schemaMeta: buildSchemaMeta(),
      format: 'dc+sd-jwt',
      resolvedReferences,
    })

    expect(template.credentialConfiguration.claims).toEqual([{ path: ['given_name'] }])
  })

  it('throws when the format is absent from the catalogue entry', () => {
    expect(() =>
      buildCredentialConfigurationTemplate({
        schemaMeta: buildSchemaMeta(),
        format: 'mso_mdoc',
      })
    ).toThrow(/no schemaURI for format/)
  })
})

describe('validateIssuerMetadataAgainstProfile', () => {
  it('accepts conformant issuer metadata', () => {
    const result = validateIssuerMetadataAgainstProfile({
      issuerMetadata: conformantIssuerMetadata(),
      schemaMeta: buildSchemaMeta(PROFILE),
      format: 'dc+sd-jwt',
    })

    expect(result).toEqual({ valid: true, errors: [] })
  })

  it('reports a missing configuration for the credential type', () => {
    const result = validateIssuerMetadataAgainstProfile({
      issuerMetadata: { credential_configurations_supported: {} },
      schemaMeta: buildSchemaMeta(),
      format: 'dc+sd-jwt',
    })

    expect(result.valid).toBe(false)
    expect(result.errors[0]?.message).toContain(VCT)
  })

  it('rejects signing algorithms outside the profile', () => {
    const metadata = conformantIssuerMetadata()
    const configuration = (metadata.credential_configurations_supported as Record<string, Record<string, unknown>>)[VCT]
    configuration.credential_signing_alg_values_supported = ['ES256', 'RS256']

    const result = validateIssuerMetadataAgainstProfile({
      issuerMetadata: metadata,
      schemaMeta: buildSchemaMeta(PROFILE),
      format: 'dc+sd-jwt',
    })

    expect(result.valid).toBe(false)
    expect(result.errors).toContainEqual({
      path: `credential_configurations_supported.${VCT}.credential_signing_alg_values_supported`,
      message: 'not permitted by the issuance profile: RS256',
    })
  })

  it('rejects proof types outside the profile and missing key attestation', () => {
    const metadata = conformantIssuerMetadata()
    const configuration = (metadata.credential_configurations_supported as Record<string, Record<string, unknown>>)[VCT]
    configuration.proof_types_supported = {
      jwt: { proof_signing_alg_values_supported: ['ES256'] },
      ldp_vp: { proof_signing_alg_values_supported: ['ES256'] },
    }

    const result = validateIssuerMetadataAgainstProfile({
      issuerMetadata: metadata,
      schemaMeta: buildSchemaMeta(PROFILE),
      format: 'dc+sd-jwt',
    })

    expect(result.valid).toBe(false)
    expect(result.errors.map((error) => error.path)).toEqual([
      `credential_configurations_supported.${VCT}.proof_types_supported.jwt.key_attestations_required`,
      `credential_configurations_supported.${VCT}.proof_types_supported.ldp_vp`,
    ])
  })

  it('rejects batch issuance when the profile forbids it', () => {
    const metadata = conformantIssuerMetadata()
    metadata.batch_credential_issuance = { batch_size: 5 }

    const result = validateIssuerMetadataAgainstProfile({
      issuerMetadata: metadata,
      schemaMeta: buildSchemaMeta(PROFILE),
      format: 'dc+sd-jwt',
    })

    expect(result.valid).toBe(false)
    expect(result.errors).toContainEqual({
      path: 'batch_credential_issuance',
      message: 'batch issuance is not permitted by the issuance profile',
    })
  })

  it('still requires proof types for key binding without a profile', () => {
    const metadata = conformantIssuerMetadata()
    const configuration = (metadata.credential_configurations_supported as Record<string, Record<string, unknown>>)[VCT]
    delete configuration.proof_types_supported

    const result = validateIssuerMetadataAgainstProfile({
      issuerMetadata: metadata,
      schemaMeta: buildSchemaMeta(),
      format: 'dc+sd-jwt',
    })

    expect(result.valid).toBe(false)
    expect(result.errors[0]?.path).toBe(`credential_configurations_supported.${VCT}.proof_types_supported`)
  })
})
