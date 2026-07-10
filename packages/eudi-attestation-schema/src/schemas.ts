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

export const AttestationFormatSchema = z.enum(AttestationFormatValues)

export const AttestationLoSValues = [
  'iso_18045_high',
  'iso_18045_moderate',
  'iso_18045_enhanced-basic',
  'iso_18045_basic',
] as const

export const AttestationLoSSchema = z.enum(AttestationLoSValues)

export const BindingTypeValues = ['claim', 'key', 'biometric', 'none'] as const

export const BindingTypeSchema = z.enum(BindingTypeValues)

export const FrameworkTypeValues = ['etsi_tl'] as const

export const FrameworkTypeSchema = z.enum(FrameworkTypeValues)

// ============================================================================
// TrustAuthority Sub-class (Section 4.3.3)
// ============================================================================

export const TrustAuthoritySchema = z
  .object({
    frameworkType: FrameworkTypeSchema,
    value: z.string().min(1),
  })
  .strict()

// ============================================================================
// SchemaURI Meta Sub-schemas
// ============================================================================

/**
 * Credential-type metadata for dc+sd-jwt format.
 * vct identifies the credential type per SD-JWT VC spec.
 */
export const SdJwtMetaSchema = z
  .object({
    vct: z.string().min(1),
  })
  .strict()

/**
 * Credential-type metadata for mso_mdoc format.
 * doctype_value is required.
 */
export const MsoMdocMetaSchema = z
  .object({
    doctype_value: z.string().min(1),
  })
  .strict()

const Sha256SriSchema = z
  .string()
  .regex(/^sha256-[A-Za-z0-9+/]+={0,2}$/, 'integrity must be a sha256 SRI value (sha256-<base64>)')

// ============================================================================
// Schema Sub-class (Section 4.3.2)
// ============================================================================

const _schemaURIBase = {
  uri: z.string().url(),
  integrity: Sha256SriSchema,
}

export const SchemaURISchema = z.discriminatedUnion('formatIdentifier', [
  z.object({ ..._schemaURIBase, formatIdentifier: z.literal('dc+sd-jwt'), meta: SdJwtMetaSchema }),
  z.object({ ..._schemaURIBase, formatIdentifier: z.literal('mso_mdoc'), meta: MsoMdocMetaSchema }),
])

// ============================================================================
// SchemaMeta Main Class (Section 4.3.1)
// ============================================================================

export const SchemaMetaSchema = z
  .object({
    id: z.string().url(),
    iat: z.number().int().nonnegative().optional(),
    version: z.string().min(1),
    rulebookURI: z.string().url(),
    rulebookIntegrity: Sha256SriSchema,
    trustedAuthorities: z.array(TrustAuthoritySchema).optional(),
    attestationLoS: AttestationLoSSchema,
    bindingType: BindingTypeSchema,
    schemaURIs: z.array(SchemaURISchema).min(1),
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
  })
