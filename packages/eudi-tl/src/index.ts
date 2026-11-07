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
  TslType,
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
  type ParseTrustedListOptions,
  parseTrustedList,
  type TrustAnchorFilter,
  type TrustedListPointerFilter,
} from './parse'
export { TrustedListProfiles } from './profiles'
export {
  TrustedListError,
  TrustedListParseError,
  TrustedListSignatureError,
  TrustedListValidationError,
} from './trusted-list-error'
export {
  type DigitalIdentity,
  type ServiceHistoryInstance,
  type TrustAnchor,
  type TrustedList,
  type TrustedListPointer,
  type TrustedListService,
  type TrustServiceProvider,
  zDigitalIdentity,
  zServiceHistoryInstance,
  zTrustAnchor,
  zTrustedList,
  zTrustedListPointer,
  zTrustedListService,
  zTrustServiceProvider,
} from './types'
export {
  assertValidTrustedList,
  type ProfileRule,
  TRUSTED_LIST_VALIDATION_CODES,
  type TrustedListValidationCode,
  type TrustedListValidationIssue,
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

import { type ParseTrustedListOptions, parseTrustedList } from './parse'
import { TrustedListSignatureError } from './trusted-list-error'
import type { TrustedList } from './types'
import { type VerifyTrustedListOptions, verifyTrustedListSignature } from './verify'

/**
 * Verify the trusted list signature against the `trustAnchors` and, only if it
 * is valid, parse it. This is the safe entry point: it never returns a
 * {@link TrustedList} whose authenticity has not been established.
 *
 * @throws TrustedListSignatureError when `trustAnchors` is missing or empty, or the signature is not valid.
 */
export async function loadTrustedList(
  xml: string,
  options: Required<VerifyTrustedListOptions> & ParseTrustedListOptions
): Promise<TrustedList> {
  // Without them, the signature check would only establish the integrity of the list
  if (!options?.trustAnchors) {
    throw new TrustedListSignatureError('loadTrustedList needs the trustAnchors of the scheme operator')
  }
  await verifyTrustedListSignature(xml, options)
  return parseTrustedList(xml, options)
}
