/**
 * WRPRC Zod Schemas
 *
 * Zod schemas for ETSI TS 119 475 (Wallet-Relying Party Registration Certificates).
 * Types are derived from these schemas via z.infer<>.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import { z } from 'zod'

// ============================================================================
// Multilingual Value Schemas
// ============================================================================

/**
 * Multilingual string schema (B.2.6 Class MultiLangString)
 */
export const MultiLangStringSchema = z.object({
  /** Language code per BCP47/RFC 5646 */
  lang: z.string().min(2),
  /** Localized string value */
  content: z.string().min(1),
})

// ============================================================================
// Identity Schemas
// ============================================================================

/**
 * Supervisory Authority schema for Data Protection Authority
 */
export const SupervisoryAuthoritySchema = z.object({
  /** Email address of the Data Protection Authority */
  email: z.email().optional(),
  /** Telephone number of the Data Protection Authority */
  phone: z.string().optional(),
  /** URL of web form provided by the Data Protection Authority */
  uri: z.url().optional(),
})

/**
 * Claim schema for credential attribute specification (B.2.10 Class Claim)
 */
export const ClaimSchema = z.object({
  /** Path pointer that specifies the path to a claim within the Credential */
  path: z.array(z.string()).min(1),
  /** Array of expected values of the claim */
  values: z.array(z.union([z.string(), z.number(), z.boolean()])).optional(),
})

/**
 * Credential schema for attestations (B.2.9 Class Credential)
 */
export const CredentialSchema = z.object({
  /** Format of the attestation (e.g., "dc+sd-jwt", "mso_mdoc") */
  format: z.string().min(1),
  /** Object defining additional properties per Credential Format */
  meta: z.record(z.string(), z.unknown()),
  /** Array of claim objects specifying requestable attributes */
  claim: z.array(ClaimSchema).optional(),
})

/**
 * Status list reference for certificate validity
 */
export const StatusListSchema = z.object({
  /** Index in the status list */
  idx: z.number().int().nonnegative(),
  /** URI to the status list */
  uri: z.url(),
})

/**
 * Status schema for WRPRC validity
 */
export const StatusSchema = z.object({
  status_list: StatusListSchema,
})

/**
 * Intermediary information when WRP acts through an intermediary
 */
export const IntermediarySchema = z.object({
  /** Identifier of the intermediary */
  sub: z.string().min(1),
  /** Name of the intermediary */
  name: z.string().min(1),
})

// ============================================================================
// WRPRC Payload Schema
// ============================================================================

/**
 * WRPRC Payload schema according to ETSI TS 119 475 clause 5.2.4
 */
export const WRPRCPayloadSchema = z.object({
  /** The subject trade name of the WRPRC (B.2.1 tradeName) */
  name: z.string().min(1),

  /** Legal name for legal person (B.2.3 legalName) */
  sub_ln: z.string().optional(),

  /** Given name for natural person (B.2.4 givenName) */
  sub_gn: z.string().optional(),

  /** Family name for natural person (B.2.4 familyName) */
  sub_fn: z.string().optional(),

  /** WRP identifier following semantic identifier rules */
  sub: z.string().min(1),

  /** Country code (ISO 3166-1 Alpha-2) */
  country: z.string().length(2),

  /** URL pointing to the national registry API endpoint */
  registry_uri: z.url(),

  /** Descriptions of the services provided by the WRP */
  srv_description: z.array(z.array(MultiLangStringSchema)).optional(),

  /** List of entitlements assigned to the WRP */
  entitlements: z.array(z.url()).min(1),

  /** URL to the WRP's privacy policy */
  privacy_policy: z.url().optional(),

  /** URL general-purpose web address */
  info_uri: z.url().optional(),

  /** URL or email for data deletion/portability requests */
  support_uri: z.url().or(z.email()).optional(),

  /** Data Protection Authority supervising the WRP */
  supervisory_authority: SupervisoryAuthoritySchema.optional(),

  /** Policy identifier as defined in clause 6.1.3 */
  policy_id: z.array(z.string()).optional(),

  /** URL to the certificate policy and practice statement */
  certificate_policy: z.url().optional(),

  /** Status list for WRPRC validity */
  status: StatusSchema.optional(),

  /** Purpose of the intended data processing */
  purpose: z.array(MultiLangStringSchema).optional(),

  /** Set of credentials intended to be requested by the WRP */
  credentials: z.array(CredentialSchema).optional(),

  /** Set of credentials issued by the WRP (for attestation providers) */
  provides_attestations: z.array(CredentialSchema).optional(),

  /** Intermediary information when WRP acts through an intermediary */
  intermediary: IntermediarySchema.optional(),
})

// ============================================================================
// WRPRC Header Schemas
// ============================================================================

/**
 * JWT Header schema according to ETSI TS 119 475 clause 5.2.2
 */
export const WRPRCJWTHeaderSchema = z.object({
  /** Type of the Web Token - must be "rc-wrp+jwt" for JWT */
  typ: z.literal('rc-wrp+jwt'),
  /** Algorithm used to sign the JWT */
  alg: z.enum(['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512']),
  /** Certificate chain to verify the JWT */
  x5c: z.array(z.string()).min(1),
  /** Key ID */
  kid: z.string().optional(),
  /** Unix timestamp indicating when the WRPRC was issued */
  iat: z.number().int().positive(),
})

/**
 * CWT Header schema according to ETSI TS 119 475 clause 5.2.3
 */
export const WRPRCCWTHeaderSchema = z.object({
  /** Type of the Web Token - must be "rc-wrp+cwt" for CWT */
  typ: z.literal('rc-wrp+cwt'),
  /** Algorithm used to sign the CWT per RFC 9052 */
  alg: z.number().int(),
  /** Certificate chain to verify the CWT per RFC 9360 */
  x5chain: z.array(z.instanceof(Uint8Array)).min(1),
  /** Unix timestamp indicating when the WRPRC was issued */
  iat: z.number().int().positive(),
})

// ============================================================================
// Complete WRPRC Document Schemas
// ============================================================================

/**
 * Complete JWT WRPRC schema
 */
export const WRPRCJWTSchema = z.object({
  header: WRPRCJWTHeaderSchema,
  payload: WRPRCPayloadSchema,
})

/**
 * Complete CWT WRPRC schema
 */
export const WRPRCCWTSchema = z.object({
  header: WRPRCCWTHeaderSchema,
  payload: WRPRCPayloadSchema,
})

// ============================================================================
// Legal Person Subject Schema (for validation)
// ============================================================================

/**
 * Schema for legal person WRPRC subject
 */
export const LegalPersonSubjectSchema = WRPRCPayloadSchema.extend({
  sub_ln: z.string().min(1),
}).omit({
  sub_gn: true,
  sub_fn: true,
})

/**
 * Schema for natural person WRPRC subject
 */
export const NaturalPersonSubjectSchema = WRPRCPayloadSchema.extend({
  sub_gn: z.string().min(1),
  sub_fn: z.string().min(1),
}).omit({
  sub_ln: true,
})
