import { base64 } from '@owf/identity-common'
import { EU_LOTL_SIGNING_CERTIFICATES } from './eu-lotl-anchors'
import { parseTrustedList } from './parse'
import { TrustedListProfiles } from './profiles'
import { TrustedListParseException } from './trusted-list-exception'
import type { TrustedList } from './types'
import { validateTrustedListProfile } from './validate'
import { type VerifyTrustedListOptions, type VerifyTrustedListResult, verifyTrustedListSignature } from './verify'

/**
 * The LOTL signing certificates shipped with this package, as DER bytes ready
 * to pass as `trustAnchors`.
 *
 * This pinned set is the root of the eIDAS trusted-list hierarchy and cannot be
 * bootstrapped from the LOTL itself — a forged list would carry a forged
 * self-pointer. It is published by the European Commission in the Official
 * Journal; see {@link EU_LOTL_ANCHORS_PROVENANCE} for the exact act, list issue
 * and expiry of the shipped set.
 *
 * Certificates rotate (historically every 6–24 months), so a deployment has
 * three ways to stay current without waiting for a release of this package:
 *
 * 1. pass its own `trustAnchors`, e.g. from configuration;
 * 2. after verifying a LOTL, read the currently published set from its own
 *    self-pointer with `getPointerSigningCertificates(lotl, { tslType:
 *    TSLType.EUlistofthelists })` and persist it — rotation is announced in a
 *    list still signed by the previous generation of keys;
 * 3. follow the pivot LOTLs advertised in the list's `SchemeInformationURI`
 *    when the pinned set has fallen behind entirely.
 */
export function getEuLotlTrustAnchors(): Uint8Array[] {
  return EU_LOTL_SIGNING_CERTIFICATES.map((entry) => base64.decode(entry.certificate))
}

/**
 * Verify the signature of the EU List of Trusted Lists against the shipped
 * signing certificates. Identical to {@link verifyTrustedListSignature} except
 * that `trustAnchors` defaults to {@link getEuLotlTrustAnchors} instead of to
 * "integrity only" — pass your own to override.
 */
export function verifyEuLotlSignature(
  xml: string,
  options: VerifyTrustedListOptions = {}
): Promise<VerifyTrustedListResult> {
  return verifyTrustedListSignature(xml, { ...options, trustAnchors: options.trustAnchors ?? getEuLotlTrustAnchors() })
}

/**
 * Verify, parse and profile-check the EU List of Trusted Lists in one step: the
 * safe entry point for the top of the hierarchy. The returned list carries the
 * `PointersToOtherTSL` entries from which national list anchors are derived
 * with `getPointerSigningCertificates`.
 */
export async function loadEuLotl(xml: string, options: VerifyTrustedListOptions = {}): Promise<TrustedList> {
  await verifyEuLotlSignature(xml, options)
  const lotl = parseTrustedList(xml)
  const profile = validateTrustedListProfile(lotl, TrustedListProfiles.euLotl)
  if (!profile.valid) {
    const details = profile.errors.map((error) => `${error.path}: ${error.message}`).join('; ')
    throw new TrustedListParseException(`Not a conforming EU List of Trusted Lists: ${details}`)
  }
  return lotl
}
