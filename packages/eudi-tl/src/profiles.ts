import { ServiceStatus, ServiceType, TSLType } from './constants'
import type { ProfileRule } from './validate'

/** Every standard TS 119 612 service status (clause 5.5.4). */
const ALL_SERVICE_STATUSES: string[] = Object.values(ServiceStatus)

/** The standard qualified `ServiceTypeIdentifier` values (Annex D). */
const QUALIFIED_SERVICE_TYPES: string[] = Object.values(ServiceType)

/**
 * Ready-made {@link ProfileRule}s for common ETSI ecosystems, so callers don't
 * have to hand-write the URIs. The engine ({@link validateTrustedListProfile})
 * stays profile-agnostic; these are just convenience constants you pass into it.
 *
 * A profile is an allowlist: the structural schema is checked first, then the
 * list's `TSLType` must match and every service's type/status must be permitted.
 * That fits homogeneous, curated lists well (e.g. Age Verification). For a full
 * eIDAS national list — which legitimately carries withdrawn/ceased services and
 * a broad mix of qualified service types — {@link euGeneric} therefore permits
 * all standard ETSI statuses and qualified service types: it asserts "this is a
 * well-formed EU generic list using standard ETSI URIs", not "only currently
 * active CAs". Narrow further with your own {@link ProfileRule} when you need to.
 */
export const TrustedListProfiles = {
  /**
   * EU List of Trusted Lists (LOTL). Its `TSLType` is `EUlistofthelists` and it
   * carries pointers to national lists rather than trust-service providers, so
   * no service type/status is permitted (a conforming LOTL has no TSP services).
   */
  euLotl: {
    name: 'eu-lotl',
    tslType: TSLType.EUlistofthelists,
    serviceTypes: [],
    serviceStatuses: [],
  },
  /**
   * A generic EU (eIDAS national) trusted list: `TSLType` `EUgeneric`, any
   * standard qualified service type, any standard service status (including
   * withdrawn/ceased entries that national lists retain for history).
   */
  euGeneric: {
    name: 'eu-generic',
    tslType: TSLType.EUgeneric,
    serviceTypes: QUALIFIED_SERVICE_TYPES,
    serviceStatuses: ALL_SERVICE_STATUSES,
  },
  /**
   * EU Age Verification trusted list, per the European Commission's "AV Trusted
   * List Specifications" (DIGIT.B.3). The `TSLType` (clause 5.3.3), the single
   * Proof of Age Attestation service type (`paa`, clause 5.5.1) and the two
   * permitted service statuses (clause 5.5.4) are fixed by that specification —
   * which states the statuses "may be used to the exclusion of any other", so
   * the allowlist model captures the AV profile exactly. Deployed lists have
   * used `https` for the `TSLType`; the profile compares scheme-insensitively.
   */
  ageVerification: {
    name: 'eu-age-verification',
    tslType: 'http://trust.tech.ec.europa.eu/lists/age-verification/tsl-type',
    serviceTypes: ['http://trust.tech.ec.europa.eu/lists/age-verification/service-type/paa'],
    serviceStatuses: [
      'http://trust.tech.ec.europa.eu/lists/age-verification/service-status/recognized',
      'http://trust.tech.ec.europa.eu/lists/age-verification/service-status/deprecated',
    ],
  },
} satisfies Record<string, ProfileRule>
