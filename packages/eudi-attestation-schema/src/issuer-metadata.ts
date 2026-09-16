/**
 * Mapping between a TS11 SchemaMeta catalogue entry and OID4VCI Credential Issuer Metadata.
 *
 * The catalogue is the normative source for what is type-determined (format, vct/doctype,
 * claims) and what is policy-determined (the optional `issuanceProfile`). Deployment-specific
 * members stay with the issuer and are never emitted here.
 *
 * @see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata
 */

import { getClaimsFromSchema } from './dcql'
import { SchemaMetaException } from './schema-meta-exception'
import type {
  AttestationFormat,
  BuildCredentialConfigurationTemplateOptions,
  CredentialConfigurationTemplate,
  ResolvedSchemaReference,
  SchemaMeta,
  SchemaURI,
  ValidateIssuerMetadataOptions,
} from './types'
import type { ValidationError, ValidationResult } from './validator'

const CONFIGURATION_DEPLOYMENT_FIELDS = ['scope', 'display']
const ISSUER_METADATA_DEPLOYMENT_FIELDS = [
  'credential_issuer',
  'credential_endpoint',
  'authorization_servers',
  'nonce_endpoint',
]

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function getSchemaURI(schemaMeta: SchemaMeta, format: AttestationFormat): SchemaURI {
  const entry = schemaMeta.schemaURIs.find((value) => value.formatIdentifier === format)

  if (!entry) {
    throw new SchemaMetaException(`SchemaMeta has no schemaURI for format '${format}'`)
  }

  return entry
}

function getCredentialTypeIdentifier(schemaURI: SchemaURI): string {
  return schemaURI.formatIdentifier === 'dc+sd-jwt' ? schemaURI.meta.vct : schemaURI.meta.doctype_value
}

function findResolvedReference(
  format: AttestationFormat,
  resolvedReferences?: ResolvedSchemaReference[]
): ResolvedSchemaReference | undefined {
  return resolvedReferences?.find((reference) => reference.format === format)
}

/**
 * Build an OID4VCI `credential_configurations_supported` entry from a catalogue entry.
 *
 * Type-determined members are filled in, policy-determined members are taken from the optional
 * `issuanceProfile`, and deployment-specific members are left out and reported in
 * `deploymentFields` for the issuer to supply.
 */
export function buildCredentialConfigurationTemplate(
  options: BuildCredentialConfigurationTemplateOptions
): CredentialConfigurationTemplate {
  const { schemaMeta, format, resolvedReferences, credentialConfigurationId } = options
  const schemaURI = getSchemaURI(schemaMeta, format)
  const credentialConfiguration: Record<string, unknown> = { format }
  const metadata = schemaURI.meta.credential_metadata
  if (metadata?.display) {
    credentialConfiguration.display = metadata.display.map((entry) => ({
      ...entry,
    }))
  }
  if (metadata?.claims) {
    credentialConfiguration.claims = metadata.claims
  }

  if (schemaURI.formatIdentifier === 'dc+sd-jwt') {
    credentialConfiguration.vct = schemaURI.meta.vct
  } else {
    credentialConfiguration.doctype = schemaURI.meta.doctype_value
  }

  const claims = getClaimsFromSchema(findResolvedReference(format, resolvedReferences))
  if (claims.length > 0 && credentialConfiguration.claims === undefined) {
    credentialConfiguration.claims = claims.map((claim) => ({
      path: claim.path,
    }))
  }

  const profile = schemaMeta.issuanceProfile

  if (profile?.credentialSigningAlgValuesSupported) {
    credentialConfiguration.credential_signing_alg_values_supported = [...profile.credentialSigningAlgValuesSupported]
  }

  if (profile?.cryptographicBindingMethodsSupported) {
    credentialConfiguration.cryptographic_binding_methods_supported = [...profile.cryptographicBindingMethodsSupported]
  }

  if (profile?.proofTypesSupported) {
    credentialConfiguration.proof_types_supported = Object.fromEntries(
      Object.entries(profile.proofTypesSupported).map(([proofType, value]) => [
        proofType,
        {
          proof_signing_alg_values_supported: [...value.proof_signing_alg_values_supported],
          ...(profile.keyAttestationRequired ? { key_attestations_required: {} } : {}),
        },
      ])
    )
  }

  return {
    credentialConfigurationId: credentialConfigurationId ?? getCredentialTypeIdentifier(schemaURI),
    credentialConfiguration,
    deploymentFields: {
      credentialConfiguration: [...CONFIGURATION_DEPLOYMENT_FIELDS],
      issuerMetadata: [...ISSUER_METADATA_DEPLOYMENT_FIELDS],
    },
  }
}

function checkSubset(
  actual: unknown,
  allowed: string[],
  path: string,
  errors: ValidationError[]
): string[] | undefined {
  if (actual === undefined) {
    return undefined
  }

  if (!Array.isArray(actual) || actual.some((value) => typeof value !== 'string')) {
    errors.push({ path, message: 'must be an array of strings' })
    return undefined
  }

  const values = actual as string[]
  const disallowed = values.filter((value) => !allowed.includes(value))

  if (disallowed.length > 0) {
    errors.push({
      path,
      message: `not permitted by the issuance profile: ${disallowed.join(', ')}`,
    })
  }

  return values
}

function validateProofTypes(
  configuration: Record<string, unknown>,
  profile: NonNullable<SchemaMeta['issuanceProfile']>,
  base: string,
  errors: ValidationError[]
): void {
  const allowedProofTypes = profile.proofTypesSupported
  if (!allowedProofTypes) {
    return
  }

  const proofTypes = configuration.proof_types_supported
  if (proofTypes === undefined) {
    return
  }

  if (!isPlainObject(proofTypes)) {
    errors.push({
      path: `${base}.proof_types_supported`,
      message: 'must be an object',
    })
    return
  }

  for (const [proofType, rawValue] of Object.entries(proofTypes)) {
    const proofPath = `${base}.proof_types_supported.${proofType}`
    const allowed = allowedProofTypes[proofType]

    if (!allowed) {
      errors.push({
        path: proofPath,
        message: 'proof type is not permitted by the issuance profile',
      })
      continue
    }

    if (!isPlainObject(rawValue)) {
      errors.push({ path: proofPath, message: 'must be an object' })
      continue
    }

    checkSubset(
      rawValue.proof_signing_alg_values_supported,
      allowed.proof_signing_alg_values_supported,
      `${proofPath}.proof_signing_alg_values_supported`,
      errors
    )

    if (profile.keyAttestationRequired && rawValue.key_attestations_required === undefined) {
      errors.push({
        path: `${proofPath}.key_attestations_required`,
        message: 'is required by the issuance profile',
      })
    }
  }
}

function validateConfiguration(
  params: {
    configuration: Record<string, unknown>
    schemaMeta: SchemaMeta
    format: AttestationFormat
    typeMember: string
    expectedTypeIdentifier: string
    base: string
  },
  errors: ValidationError[]
): void {
  const { configuration, schemaMeta, format, typeMember, expectedTypeIdentifier, base } = params

  if (configuration.format !== format) {
    errors.push({ path: `${base}.format`, message: `must be '${format}'` })
  }

  if (configuration[typeMember] !== expectedTypeIdentifier) {
    errors.push({
      path: `${base}.${typeMember}`,
      message: `must be '${expectedTypeIdentifier}'`,
    })
  }

  if (schemaMeta.bindingType === 'key' && configuration.proof_types_supported === undefined) {
    errors.push({
      path: `${base}.proof_types_supported`,
      message: "is required when the catalogue entry declares bindingType 'key'",
    })
  }

  const profile = schemaMeta.issuanceProfile
  if (!profile) {
    return
  }

  if (profile.credentialSigningAlgValuesSupported) {
    checkSubset(
      configuration.credential_signing_alg_values_supported,
      profile.credentialSigningAlgValuesSupported,
      `${base}.credential_signing_alg_values_supported`,
      errors
    )
  }

  if (profile.cryptographicBindingMethodsSupported) {
    checkSubset(
      configuration.cryptographic_binding_methods_supported,
      profile.cryptographicBindingMethodsSupported,
      `${base}.cryptographic_binding_methods_supported`,
      errors
    )
  }

  validateProofTypes(configuration, profile, base, errors)
}

function findMatchingConfigurations(
  configurations: Record<string, unknown>,
  params: {
    format: AttestationFormat
    typeMember: string
    expectedTypeIdentifier: string
    credentialConfigurationId?: string
  }
): Array<[string, unknown]> {
  const { format, typeMember, expectedTypeIdentifier, credentialConfigurationId } = params

  if (credentialConfigurationId !== undefined) {
    return Object.entries(configurations).filter(([id]) => id === credentialConfigurationId)
  }

  return Object.entries(configurations).filter(
    ([, configuration]) =>
      isPlainObject(configuration) &&
      configuration.format === format &&
      configuration[typeMember] === expectedTypeIdentifier
  )
}

/**
 * Check that a published Credential Issuer Metadata document is consistent with a catalogue
 * entry: the credential type matches, and every policy-determined value stays inside the bounds
 * of the optional `issuanceProfile`.
 *
 * `statusMechanism` and `maxValidityPeriod` are not expressible in issuer metadata and are
 * therefore not checked here.
 */
export function validateIssuerMetadataAgainstProfile(options: ValidateIssuerMetadataOptions): ValidationResult {
  const { issuerMetadata, schemaMeta, format, credentialConfigurationId } = options
  const errors: ValidationError[] = []

  if (!isPlainObject(issuerMetadata)) {
    return {
      valid: false,
      errors: [{ path: '', message: 'issuer metadata must be an object' }],
    }
  }

  const configurations = issuerMetadata.credential_configurations_supported
  if (!isPlainObject(configurations)) {
    return {
      valid: false,
      errors: [
        {
          path: 'credential_configurations_supported',
          message: 'must be an object',
        },
      ],
    }
  }

  const schemaURI = getSchemaURI(schemaMeta, format)
  const expectedTypeIdentifier = getCredentialTypeIdentifier(schemaURI)
  const typeMember = format === 'dc+sd-jwt' ? 'vct' : 'doctype'

  const matches = findMatchingConfigurations(configurations, {
    format,
    typeMember,
    expectedTypeIdentifier,
    credentialConfigurationId,
  })

  if (matches.length === 0) {
    return {
      valid: false,
      errors: [
        {
          path: 'credential_configurations_supported',
          message: `no configuration found for format '${format}' with ${typeMember} '${expectedTypeIdentifier}'`,
        },
      ],
    }
  }

  for (const [id, rawConfiguration] of matches) {
    const base = `credential_configurations_supported.${id}`

    if (!isPlainObject(rawConfiguration)) {
      errors.push({ path: base, message: 'must be an object' })
      continue
    }

    validateConfiguration(
      {
        configuration: rawConfiguration,
        schemaMeta,
        format,
        typeMember,
        expectedTypeIdentifier,
        base,
      },
      errors
    )
  }

  if (
    schemaMeta.issuanceProfile?.batchIssuanceAllowed === false &&
    issuerMetadata.batch_credential_issuance !== undefined
  ) {
    errors.push({
      path: 'batch_credential_issuance',
      message: 'batch issuance is not permitted by the issuance profile',
    })
  }

  return { valid: errors.length === 0, errors }
}
