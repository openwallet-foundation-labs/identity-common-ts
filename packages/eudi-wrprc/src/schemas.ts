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
  value: z.string().min(1),
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
 * Claim schema for credential attribute specification (B.2.10 Class Claim).
 *
 * `path` follows the DCQL claims path pointer: string for an object key, integer for an
 * array index, null to select every element of an array.
 */
export const ClaimSchema = z.object({
  /** Path pointer that specifies the path to a claim within the Credential */
  path: z.array(z.union([z.string(), z.number().int(), z.null()])).min(1),
  /** Array of expected values of the claim */
  values: z.array(z.union([z.string(), z.number(), z.boolean()])).optional(),
})

/**
 * Credential schema for attestations (B.2.9 Class Credential).
 *
 * The subfield is named `claim` (singular) even though it holds an array. This follows
 * ETSI TS 119 475 v1.2.1 Tables 8 and 9 and Annex C verbatim; see the package README.
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
 * Intermediary information when WRP acts through an intermediary (Table 10).
 * The intermediary's semantic identifier comes from its own WRPAC.
 *
 * The common name subfield is `sname` per the normative Table 10. The informative
 * Annex C example spells it `name`; see the package README.
 */
export const IntermediarySchema = z.object({
  /** Semantic identifier of the intermediary (from the intermediary's WRPAC) */
  sub: z.string().min(1),
  /** Common name of the intermediary */
  sname: z.string().min(1),
})

/**
 * The "actor" claim (Table 10, GEN-5.2.4-09): under intermediation, identifies
 * the intermediary acting on behalf of the subject. `act.sub` matches `intermediary.sub`.
 */
export const ActSchema = z.object({
  /** Semantic identifier of the acting intermediary */
  sub: z.string().min(1),
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

  /** Descriptions of the services provided by the WRP (array of arrays of localized values) */
  srv_description: z.array(z.array(MultiLangStringSchema)).optional(),

  /** List of entitlements assigned to the WRP (Annex A.2 URI or OID form) */
  entitlements: z.array(z.string().min(1)).min(1),

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

  /**
   * Unique identifier of this WRPRC (RFC 7519 `jti`).
   *
   * Not listed in ETSI TS 119 475, which leaves the certificate without an identifier
   * to reference it by. Optional so that WRPRCs issued without one still validate.
   */
  jti: z.string().min(1).optional(),

  /** Issuance time as a Unix timestamp (Table 7) */
  iat: z.number().int().positive(),

  /** Status list for WRPRC validity */
  status: StatusSchema.optional(),

  /** Purpose of the intended data processing (localized values) */
  purpose: z.array(MultiLangStringSchema).optional(),

  /** Set of credentials intended to be requested by the WRP */
  credentials: z.array(CredentialSchema).optional(),

  /**
   * Set of credentials issued by the WRP (for attestation providers, Table 8).
   *
   * v1.2.1 defines this as `Credential` objects. An array of URLs pointing at the
   * machine-readable schemes in the Catalogue of Attestations, anticipated for a later
   * edition and already emitted by some SDKs, is accepted when parsing.
   */
  provides_attestations: z.union([z.array(CredentialSchema), z.array(z.url())]).optional(),

  /** Intermediary information when WRP acts through an intermediary (Table 10) */
  intermediary: IntermediarySchema.optional(),

  /** Actor claim under intermediation (Table 10, GEN-5.2.4-09) */
  act: ActSchema.optional(),

  /** Whether the WRP is a public sector body (Table 10) */
  public_body: z.boolean().optional(),

  /** Expiry as a Unix timestamp; at most 12 months after `iat` (Table 10, GEN-5.2.4-08) */
  exp: z.number().int().positive().optional(),

  /** Identifier of the intended use, present only if provided by the registry (Table 9) */
  intended_use_id: z.string().min(1).optional(),
})

// ============================================================================
// WRPRC Header Schemas
// ============================================================================

/**
 * Signature algorithms permitted for JAdES B-B signatures (ETSI TS 119 182-1 clause 5.1.2),
 * referenced by GEN-5.2.1-04.
 */
export const WRPRC_JWS_ALGORITHMS = [
  'ES256',
  'ES384',
  'ES512',
  'PS256',
  'PS384',
  'PS512',
  'RS256',
  'RS384',
  'RS512',
  'EdDSA',
] as const

/**
 * JWT Header schema according to ETSI TS 119 475 clause 5.2.2 (Table 5).
 *
 * Table 5 lists `typ`, `alg` and `x5c` as the minimum set. GEN-5.2.1-04 additionally
 * requires a JAdES B-B signature, whose protected header carries `iat` as the claimed
 * signing time (ETSI TS 119 182-1 clause 5.1.9). The informative Annex C header omits it.
 */
export const WRPRCJWTHeaderSchema = z.object({
  /** Type of the Web Token - must be "rc-wrp+jwt" for JWT */
  typ: z.literal('rc-wrp+jwt'),
  /** Algorithm used to sign the JWT */
  alg: z.enum(WRPRC_JWS_ALGORITHMS),
  /** Certificate chain to verify the JWT */
  x5c: z.array(z.string()).min(1),
  /** Key ID */
  kid: z.string().optional(),
  /** JAdES claimed signing time as a Unix timestamp */
  iat: z.number().int().positive(),
})

/**
 * CWT Header schema according to ETSI TS 119 475 clause 5.2.3 (Table 6).
 *
 * GEN-5.2.1-05 requires an advanced electronic signature per RFC 9052 and RFC 9360
 * rather than a JAdES profile, so no claimed signing time is imposed here.
 */
export const WRPRCCWTHeaderSchema = z.object({
  /** Type of the Web Token - must be "rc-wrp+cwt" for CWT */
  typ: z.literal('rc-wrp+cwt'),
  /** Algorithm used to sign the CWT per RFC 9052 */
  alg: z.number().int(),
  /** Certificate chain to verify the CWT per RFC 9360 */
  x5chain: z.array(z.instanceof(Uint8Array)).min(1),
  /** Unix timestamp indicating when the WRPRC was issued (payload field, not in Table 6) */
  iat: z.number().int().positive().optional(),
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
