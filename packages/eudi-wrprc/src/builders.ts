/**
 * WRPRC Builders
 *
 * Fluent builders for creating ETSI TS 119 475 Wallet-Relying Party Registration Certificates.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import type { z } from 'zod'
import { ENTITLEMENT_SERVICE_PROVIDER, type WRP_ENTITLEMENTS } from './entitlements'
import { WRPRCPayloadSchema } from './schemas'
import type {
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

type PartialWRPRCPayload = Partial<z.input<typeof WRPRCPayloadSchema>> & {
  iat?: number
}

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
   * Add a service description in a specific language
   */
  serviceDescription(description: string, lang = 'en'): this {
    this.payload.srv_description = this.payload.srv_description ?? []
    // Each service description is an array of localized strings
    const existing = this.payload.srv_description.find((group) => group.some((d) => d.lang === lang))
    if (existing) {
      existing.push({ lang, content: description })
    } else {
      this.payload.srv_description.push([{ lang, content: description }])
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
   * Set the issued-at timestamp (Unix timestamp)
   * If not set, will default to current time when building
   */
  issuedAt(timestamp: number | Date): this {
    this.payload.iat = typeof timestamp === 'number' ? timestamp : Math.floor(timestamp.getTime() / 1000)
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
    this.payload.purpose.push({ lang, content: description })
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
   * Add a provided attestation as either a credential object or schema metadata string.
   *
   * The final payload must use one format consistently: all credentials or all strings.
   */
  addProvidedAttestation(attestation: Credential | string): this {
    const existing = this.payload.provides_attestations

    if (!existing) {
      if (typeof attestation === 'string') {
        this.payload.provides_attestations = [attestation] as string[]
      } else {
        this.payload.provides_attestations = [attestation] as Credential[]
      }
      return this
    }

    if (typeof attestation === 'string') {
      if (existing.length > 0 && typeof existing[0] !== 'string') {
        throw new WRPRCException('provides_attestations must be either an array of credentials or an array of strings')
      }
      ;(existing as string[]).push(attestation)
      return this
    }

    if (existing.length > 0 && typeof existing[0] === 'string') {
      throw new WRPRCException('provides_attestations must be either an array of credentials or an array of strings')
    }

    ;(existing as Credential[]).push(attestation)
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
   * Build the WRPRC payload
   *
   * @throws WRPRCException if the payload is invalid
   */
  build(): WRPRCPayload {
    // Set default iat if not provided
    if (!this.payload.iat) {
      this.payload.iat = Math.floor(Date.now() / 1000)
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
   * Add a simple path claim
   */
  addPathClaim(...path: string[]): this {
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
