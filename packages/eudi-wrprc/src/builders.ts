/**
 * WRPRC Builders
 *
 * Fluent builders for creating ETSI TS 119 475 Wallet-Relying Party Registration Certificates.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import { dateToSeconds, nowInSeconds } from '@owf/identity-common'
import type { z } from 'zod'
import { ENTITLEMENT_SERVICE_PROVIDER, type WRP_ENTITLEMENTS } from './entitlements'
import { WRPRCPayloadSchema } from './schemas'
import type {
  Act,
  Claim,
  Credential,
  Intermediary,
  LegalPersonWRPRCInput,
  MultiLangString,
  NaturalPersonWRPRCInput,
  Status,
  SupervisoryAuthority,
  WRPRCPayload,
} from './types'
import { WRPRCException } from './wrprc-exception'

// ============================================================================
// Partial Payload Type
// ============================================================================

type PartialWRPRCPayload = Partial<z.input<typeof WRPRCPayloadSchema>>

// ============================================================================
// WRPRC Payload Builder
// ============================================================================

/**
 * Builder for creating WRPRC payloads with a fluent API
 */
export class WRPRCBuilder {
  private payload: PartialWRPRCPayload = {}

  /**
   * Set the trade name (display name) of the WRP
   */
  name(value: string): this {
    this.payload.name = value
    return this
  }

  /**
   * Set the legal name for a legal person WRP
   */
  legalName(value: string): this {
    this.payload.sub_ln = value
    return this
  }

  /**
   * Set the given name for a natural person WRP
   */
  givenName(value: string): this {
    this.payload.sub_gn = value
    return this
  }

  /**
   * Set the family name for a natural person WRP
   */
  familyName(value: string): this {
    this.payload.sub_fn = value
    return this
  }

  /**
   * Set the WRP identifier (semantic identifier)
   *
   * @param identifier - The semantic identifier following ETSI EN 319 412-1
   *                     Format: PREFIX (3 chars) + COUNTRY (2 chars) + "-" + ID
   *                     Examples: "LEIXG-529900T8BM49AURSDO55", "TINIT-RSSMRA85T10A562S"
   */
  identifier(identifier: string): this {
    this.payload.sub = identifier
    return this
  }

  /**
   * Set the country code (ISO 3166-1 Alpha-2)
   */
  country(code: string): this {
    this.payload.country = code
    return this
  }

  /**
   * Set the URL to the national registry API endpoint
   */
  registryUri(uri: string): this {
    this.payload.registry_uri = uri
    return this
  }

  /**
   * Add a service description in a specific language.
   *
   * `srv_description` is an array of services, each localized into one or more languages
   * (B.2.1). Consecutive calls localize the same service; repeating a language starts the
   * next one.
   */
  serviceDescription(description: string, lang = 'en'): this {
    const groups = this.payload.srv_description ?? []
    this.payload.srv_description = groups
    const current = groups[groups.length - 1]
    if (current && !current.some((entry) => entry.lang === lang)) {
      current.push({ lang, value: description })
    } else {
      groups.push([{ lang, value: description }])
    }
    return this
  }

  /**
   * Add multiple service descriptions (one array per service, with multiple languages)
   */
  addServiceDescriptions(descriptions: MultiLangString[]): this {
    this.payload.srv_description = this.payload.srv_description ?? []
    this.payload.srv_description.push(descriptions)
    return this
  }

  /**
   * Add an entitlement
   *
   * @param entitlement - The entitlement URI or key from WRP_ENTITLEMENTS
   */
  addEntitlement(entitlement: string | (typeof WRP_ENTITLEMENTS)[keyof typeof WRP_ENTITLEMENTS]): this {
    this.payload.entitlements = this.payload.entitlements ?? []
    if (!this.payload.entitlements.includes(entitlement)) {
      this.payload.entitlements.push(entitlement)
    }
    return this
  }

  /**
   * Set all entitlements (replaces existing)
   */
  entitlements(entitlements: string[]): this {
    this.payload.entitlements = [...entitlements]
    return this
  }

  /**
   * Set the privacy policy URL
   */
  privacyPolicy(uri: string): this {
    this.payload.privacy_policy = uri
    return this
  }

  /**
   * Set the info URI (general-purpose web address)
   */
  infoUri(uri: string): this {
    this.payload.info_uri = uri
    return this
  }

  /**
   * Set the support URI for data requests
   */
  supportUri(uri: string): this {
    this.payload.support_uri = uri
    return this
  }

  /**
   * Set the supervisory authority (Data Protection Authority)
   */
  supervisoryAuthority(authority: SupervisoryAuthority): this {
    this.payload.supervisory_authority = authority
    return this
  }

  /**
   * Set the policy ID(s)
   */
  policyId(ids: string[]): this {
    this.payload.policy_id = ids
    return this
  }

  /**
   * Set the certificate policy URL
   */
  certificatePolicy(uri: string): this {
    this.payload.certificate_policy = uri
    return this
  }

  /**
   * Set the unique identifier of the certificate (`jti`)
   * If not set, the payload carries no identifier
   *
   * @param id - Identifier from the issuing registry's own scheme.
   */
  certificateId(id: string): this {
    this.payload.jti = id
    return this
  }

  /**
   * Set the issued-at timestamp (Unix timestamp)
   * If not set, will default to current time when building
   */
  issuedAt(timestamp: number | Date): this {
    this.payload.iat = typeof timestamp === 'number' ? timestamp : dateToSeconds(timestamp)
    return this
  }

  /**
   * Set the status reference for certificate validity
   */
  status(status: Status): this {
    this.payload.status = status
    return this
  }

  /**
   * Add a purpose description
   */
  addPurpose(description: string, lang = 'en'): this {
    this.payload.purpose = this.payload.purpose ?? []
    this.payload.purpose.push({ lang, value: description })
    return this
  }

  /**
   * Set all purposes (replaces existing)
   */
  purposes(purposes: MultiLangString[]): this {
    this.payload.purpose = purposes
    return this
  }

  /**
   * Add a credential that the WRP intends to request
   */
  addCredential(credential: Credential): this {
    this.payload.credentials = this.payload.credentials ?? []
    this.payload.credentials.push(credential)
    return this
  }

  /**
   * Add a credential issued by the WRP (Table 8, `provides_attestations`), either as a
   * `Credential` object or as a URL pointing at its machine-readable scheme.
   *
   * A payload must use one form throughout: all credentials or all URLs.
   */
  addProvidedAttestation(attestation: Credential | string): this {
    const existing = this.payload.provides_attestations

    if (!existing) {
      this.payload.provides_attestations = [attestation] as Credential[] | string[]
      return this
    }

    if (existing.length > 0 && (typeof existing[0] === 'string') !== (typeof attestation === 'string')) {
      throw new WRPRCException('provides_attestations must be either all credentials or all scheme URLs')
    }

    ;(existing as unknown[]).push(attestation)
    return this
  }

  /**
   * Set intermediary information
   */
  intermediary(intermediary: Intermediary): this {
    this.payload.intermediary = intermediary
    return this
  }

  /**
   * Set the actor claim under intermediation (Table 10, GEN-5.2.4-09)
   */
  act(act: Act): this {
    this.payload.act = act
    return this
  }

  /**
   * Mark the WRP as a public sector body (Table 10)
   */
  publicBody(value: boolean): this {
    this.payload.public_body = value
    return this
  }

  /**
   * Set the expiry timestamp (Table 10); must be at most 12 months after iat
   */
  expiresAt(timestamp: number | Date): this {
    this.payload.exp = typeof timestamp === 'number' ? timestamp : dateToSeconds(timestamp)
    return this
  }

  /**
   * Set the intended-use identifier, used to fetch the intended use from the registry (Table 9)
   */
  intendedUseId(id: string): this {
    this.payload.intended_use_id = id
    return this
  }

  /**
   * Build the WRPRC payload
   *
   * @throws WRPRCException if the payload is invalid
   */
  build(): WRPRCPayload {
    // Set default iat if not provided
    if (!this.payload.iat) {
      this.payload.iat = nowInSeconds()
    }

    const result = WRPRCPayloadSchema.safeParse(this.payload)

    if (!result.success) {
      const messages = result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n')
      throw new WRPRCException(`Invalid WRPRC payload:\n${messages}`, result.error.issues)
    }

    return result.data
  }
}

// ============================================================================
// Credential Builder
// ============================================================================

/**
 * Builder for creating Credential objects
 */
export class CredentialBuilder {
  private credential: Partial<Credential> = {}

  /**
   * Set the credential format
   *
   * @param format - The format identifier (e.g., "dc+sd-jwt", "mso_mdoc")
   */
  format(format: string): this {
    this.credential.format = format
    return this
  }

  /**
   * Set the credential metadata
   *
   * @param meta - Metadata object per credential format specification
   */
  meta(meta: Record<string, unknown>): this {
    this.credential.meta = meta
    return this
  }

  /**
   * Set SD-JWT credential metadata (vct_values)
   */
  sdJwtMeta(vctValues: string[]): this {
    this.credential.format = 'dc+sd-jwt'
    this.credential.meta = { vct_values: vctValues }
    return this
  }

  /**
   * Set mDL/mDoc credential metadata (doctype_value)
   */
  mdocMeta(doctypeValue: string): this {
    this.credential.format = 'mso_mdoc'
    this.credential.meta = { doctype_value: doctypeValue }
    return this
  }

  /**
   * Add a claim to request
   */
  addClaim(claim: Claim): this {
    this.credential.claim = this.credential.claim ?? []
    this.credential.claim.push(claim)
    return this
  }

  /**
   * Add a simple path claim. Use an integer for an array index and null to select
   * every element of an array, per the DCQL claims path pointer.
   */
  addPathClaim(...path: (string | number | null)[]): this {
    this.credential.claim = this.credential.claim ?? []
    this.credential.claim.push({ path })
    return this
  }

  /**
   * Build the Credential object
   */
  build(): Credential {
    if (!this.credential.format) {
      throw new WRPRCException('Credential format is required')
    }
    if (!this.credential.meta) {
      throw new WRPRCException('Credential meta is required')
    }
    return this.credential as Credential
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a new WRPRCBuilder
 */
export function wrprc(): WRPRCBuilder {
  return new WRPRCBuilder()
}

/**
 * Create a new CredentialBuilder
 */
export function credential(): CredentialBuilder {
  return new CredentialBuilder()
}

/**
 * Create a WRPRC payload for a legal person
 */
export function createLegalPersonWRPRC(input: LegalPersonWRPRCInput): WRPRCPayload {
  return wrprc()
    .name(input.name)
    .legalName(input.legalName)
    .identifier(input.identifier)
    .country(input.country)
    .registryUri(input.registryUri)
    .entitlements(input.entitlements)
    .build()
}

/**
 * Create a WRPRC payload for a natural person
 */
export function createNaturalPersonWRPRC(input: NaturalPersonWRPRCInput): WRPRCPayload {
  return wrprc()
    .name(input.name)
    .givenName(input.givenName)
    .familyName(input.familyName)
    .identifier(input.identifier)
    .country(input.country)
    .registryUri(input.registryUri)
    .entitlements(input.entitlements)
    .build()
}

/**
 * Create a simple service provider WRPRC
 */
export function createServiceProviderWRPRC(
  name: string,
  legalName: string,
  identifier: string,
  country: string,
  registryUri: string
): WRPRCPayload {
  return wrprc()
    .name(name)
    .legalName(legalName)
    .identifier(identifier)
    .country(country)
    .registryUri(registryUri)
    .addEntitlement(ENTITLEMENT_SERVICE_PROVIDER)
    .build()
}
