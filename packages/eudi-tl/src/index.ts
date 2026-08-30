/**
 * @owf/eudi-tl
 *
 * Parse and verify ETSI TS 119 612 XML Trusted Lists and expose normalized
 * trust anchors. Companion to `@owf/eudi-lote` (ETSI TS 119 602, JSON): both
 * resolve to the same normalized notion of a trust anchor, so a verifier can
 * consume either format and, for example, derive AKIs to send to a wallet.
 */
export {
  ACTIVE_SERVICE_STATUSES,
  ServiceStatus,
  ServiceType,
  TSLType,
} from './constants'
export {
  getEuLotlTrustAnchors,
  loadEuLotl,
  verifyEuLotlSignature,
} from './eu-lotl'
export {
  EU_LOTL_ANCHORS_PROVENANCE,
  EU_LOTL_SIGNING_CERTIFICATES,
  type EuLotlSigningCertificate,
} from './eu-lotl-anchors'
export {
  getPointerSigningCertificates,
  getTrustAnchors,
  parseTrustedList,
  type TrustAnchorFilter,
  type TrustedListPointerFilter,
} from './parse'
export { TrustedListProfiles } from './profiles'
export {
  TrustedListException,
  TrustedListParseException,
  TrustedListSignatureException,
} from './trusted-list-exception'
export {
  type DigitalIdentity,
  DigitalIdentitySchema,
  type ServiceHistoryInstance,
  ServiceHistoryInstanceSchema,
  type TrustAnchor,
  TrustAnchorSchema,
  type TrustedList,
  type TrustedListPointer,
  TrustedListPointerSchema,
  TrustedListSchema,
  type TrustedListService,
  TrustedListServiceSchema,
  type TrustServiceProvider,
  TrustServiceProviderSchema,
} from './types'
export {
  assertValidTrustedList,
  type ProfileRule,
  type ValidationError,
  type ValidationResult,
  validateTrustedList,
  validateTrustedListProfile,
} from './validate'
export {
  setTrustedListCrypto,
  type VerifyTrustedListOptions,
  type VerifyTrustedListResult,
  verifyTrustedListSignature,
} from './verify'

import { parseTrustedList } from './parse'
import type { TrustedList } from './types'
import { type VerifyTrustedListOptions, verifyTrustedListSignature } from './verify'

/**
 * Verify the trusted list signature and, only if it is valid, parse it. This is
 * the safe entry point: it never returns a {@link TrustedList} whose
 * authenticity has not been established.
 */
export async function loadTrustedList(xml: string, options: VerifyTrustedListOptions = {}): Promise<TrustedList> {
  await verifyTrustedListSignature(xml, options)
  return parseTrustedList(xml)
}
