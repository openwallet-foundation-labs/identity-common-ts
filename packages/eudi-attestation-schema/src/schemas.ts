/**
 * SchemaMeta Zod Schemas
 *
 * Zod schemas for the EUDI Catalogue of Attestations SchemaMeta data model.
 * Based on TS11 specification for interfaces and formats for the catalogue of
 * attributes and the catalogue of attestations.
 *
 * @see https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts11-interfaces-and-formats-for-catalogue-of-attributes-and-catalogue-of-schemes.md
 */

import { z } from 'zod'

// ============================================================================
// Enumerations
// ============================================================================

export const AttestationFormatValues = ['dc+sd-jwt', 'mso_mdoc'] as const

export const zAttestationFormat = z.enum(AttestationFormatValues)

export const AttestationLosValues = [
  'iso_18045_high',
  'iso_18045_moderate',
  'iso_18045_enhanced-basic',
  'iso_18045_basic',
] as const

export const zAttestationLos = z.enum(AttestationLosValues)

export const BindingTypeValues = ['claim', 'key', 'biometric', 'none'] as const

export const zBindingType = z.enum(BindingTypeValues)

export const FrameworkTypeValues = ['etsi_tl', 'x509'] as const

export const zFrameworkType = z.enum(FrameworkTypeValues)

export const VerificationMethodTypeValues = ['X509Certificate'] as const

export const zVerificationMethodType = z.enum(VerificationMethodTypeValues)

const zBase64DerCertificate = z
  .string()
  .regex(
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/,
    'x509Certificate must be a base64-encoded DER certificate'
  )
  .min(4)

const zX509CertificateVerificationMethod = z
  .object({
    type: z.literal('X509Certificate'),
    x509Certificate: zBase64DerCertificate,
  })
  .strict()

// ============================================================================
// TrustAuthority Sub-class (Section 4.3.3)
// ============================================================================

/**
 * Trust list based authority: `value` identifies the list, `verificationMethod` is how the
 * list itself is signed/verified.
 */
const zEtsiTlTrustAuthority = z
  .object({
    frameworkType: z.literal('etsi_tl'),
    value: z.string().min(1),
    verificationMethod: zX509CertificateVerificationMethod,
  })
  .strict()

/**
 * Direct root CA trust anchor: `value` is the base64-encoded DER certificate itself, so no
 * trust list needs to be hosted and no separate verificationMethod is required.
 */
const zX509TrustAuthority = z
  .object({
    frameworkType: z.literal('x509'),
    value: zBase64DerCertificate,
  })
  .strict()

export const zTrustAuthority = z.discriminatedUnion('frameworkType', [zEtsiTlTrustAuthority, zX509TrustAuthority])

// ============================================================================
// SchemaUri Meta Sub-schemas
// ============================================================================

/**
 * Portable OID4VCI display and claims metadata. It excludes issuer deployment
 * fields such as endpoints, scopes, and configuration identifiers.
 */
export const zOid4vciDisplay = z
  .object({
    name: z.string().min(1),
    locale: z.string().min(1).optional(),
    logo: z
      .object({
        uri: z.string().min(1),
        alt_text: z.string().min(1).optional(),
      })
      .strict()
      .optional(),
    description: z.string().min(1).optional(),
    background_color: z.string().min(1).optional(),
    background_image: z
      .object({
        uri: z.string().min(1),
        alt_text: z.string().min(1).optional(),
      })
      .strict()
      .optional(),
    text_color: z.string().min(1).optional(),
  })
  .strict()

const zOid4vciClaimsPath = z.array(z.union([z.string(), z.number().int().nonnegative(), z.null()])).min(1)

export const zOid4vciClaimDisplay = z
  .object({
    name: z.string().min(1).optional(),
    locale: z.string().min(1).optional(),
  })
  .strict()

export const zOid4vciClaim = z
  .object({
    path: zOid4vciClaimsPath,
    mandatory: z.boolean().optional(),
    display: z.array(zOid4vciClaimDisplay).min(1).optional(),
  })
  .strict()

export const zOid4vciCredentialMetadata = z
  .object({
    display: z.array(zOid4vciDisplay).min(1).optional(),
    claims: z.array(zOid4vciClaim).min(1).optional(),
  })
  .strict()

export const zSdJwtVcTypeMetadata = z.looseObject({
  vct: z.string().min(1),
})

/**
 * Credential-type metadata for dc+sd-jwt format.
 * vct identifies the credential type per SD-JWT VC spec.
 */
export const zSdJwtMeta = z
  .object({
    vct: z.string().min(1),
    credential_metadata: zOid4vciCredentialMetadata.optional(),
    sd_jwt_vc_metadata: zSdJwtVcTypeMetadata.optional(),
  })
  .superRefine((data, ctx) => {
    if (data.sd_jwt_vc_metadata?.vct !== undefined && data.sd_jwt_vc_metadata.vct !== data.vct) {
      ctx.addIssue({
        code: 'custom',
        path: ['sd_jwt_vc_metadata', 'vct'],
        message: 'must match meta.vct',
      })
    }
  })
  .strict()

/**
 * Credential-type metadata for mso_mdoc format.
 * doctype_value is required.
 */
export const zMsoMdocMeta = z
  .object({
    doctype_value: z.string().min(1),
    credential_metadata: zOid4vciCredentialMetadata.optional(),
  })
  .strict()

/**
 * W3C SRI integrity metadata. Only sha256 is supported, so that a catalogue entry cannot
 * declare a digest that resolution would later reject.
 */
export const zSha256Sri = z
  .string()
  .regex(
    /^sha256-(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/,
    'integrity must be a sha256 SRI value (sha256-<base64>); only sha256 is supported'
  )

// ============================================================================
// Schema Sub-class (Section 4.3.2)
// ============================================================================

const _schemaUriBase = {
  uri: z.string().url(),
  integrity: zSha256Sri,
}

export const zSchemaUri = z.discriminatedUnion('formatIdentifier', [
  z.object({
    ..._schemaUriBase,
    formatIdentifier: z.literal('dc+sd-jwt'),
    meta: zSdJwtMeta,
  }),
  z.object({
    ..._schemaUriBase,
    formatIdentifier: z.literal('mso_mdoc'),
    meta: zMsoMdocMeta,
  }),
])

// ============================================================================
// IssuanceProfile Sub-class
// ============================================================================

export const zProofType = z
  .object({
    proof_signing_alg_values_supported: z.array(z.string().min(1)).min(1),
  })
  .strict()

export const zStatusMechanism = z
  .object({
    type: z.literal('token_status_list'),
    required: z.boolean(),
  })
  .strict()

/**
 * Policy constraints an issuer of this attestation type must satisfy. Every member is an
 * allowed set or a bound, never a deployment value: the catalogue narrows the space, the
 * issuer picks a conformant point inside it.
 */
export const zIssuanceProfile = z
  .object({
    credentialSigningAlgValuesSupported: z.array(z.string().min(1)).min(1).optional(),
    cryptographicBindingMethodsSupported: z.array(z.string().min(1)).min(1).optional(),
    proofTypesSupported: z.record(z.string().min(1), zProofType).optional(),
    keyAttestationRequired: z.boolean().optional(),
    statusMechanism: zStatusMechanism.optional(),
    maxValidityPeriod: z.number().int().positive().optional(),
    batchIssuanceAllowed: z.boolean().optional(),
  })
  .strict()

// ============================================================================
// SchemaMeta Main Class (Section 4.3.1)
// ============================================================================

const zSemVer = z
  .string()
  .regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/, 'version must be a SemVer string')

export const zSchemaMeta = z
  .object({
    id: z.string().url(),
    iat: z.number().int().nonnegative().optional(),
    version: zSemVer,
    rulebookURI: z.string().url(),
    rulebookIntegrity: zSha256Sri,
    trustedAuthorities: z.array(zTrustAuthority).optional(),
    attestationLoS: zAttestationLos,
    bindingType: zBindingType,
    schemaURIs: z.array(zSchemaUri).min(1),
    issuanceProfile: zIssuanceProfile.optional(),
  })
  .superRefine((data, ctx) => {
    const seen = new Set<string>()
    for (let i = 0; i < data.schemaURIs.length; i += 1) {
      const format = data.schemaURIs[i]?.formatIdentifier
      if (seen.has(format)) {
        ctx.addIssue({
          code: 'custom',
          path: ['schemaURIs', i, 'formatIdentifier'],
          message: `duplicate formatIdentifier '${format}' is not allowed`,
        })
      }
      seen.add(format)
    }

    if (data.bindingType === 'none' && data.issuanceProfile) {
      for (const key of ['cryptographicBindingMethodsSupported', 'proofTypesSupported'] as const) {
        if (data.issuanceProfile[key] !== undefined) {
          ctx.addIssue({
            code: 'custom',
            path: ['issuanceProfile', key],
            message: `${key} must not be set when bindingType is 'none'`,
          })
        }
      }
    }
  })
