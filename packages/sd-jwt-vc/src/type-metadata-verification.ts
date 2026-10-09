import { type Disclosure, SD_DIGEST, SD_LIST_KEY } from '@sd-jwt/core'
import type { ClaimPath, ResolvedTypeMetadata, TypeMetadataFormat } from './sd-jwt-vc-type-metadata-format'

export type TypeMetadataVerificationResult = {
  /**
   * Claims present in the SD-JWT VC that are not declared in the type metadata. Only the topmost undeclared path is
   * reported. Registered SD-JWT VC claims (e.g. `iss`, `cnf`, `status`) are ignored unless the type metadata declares them.
   */
  extraClaims: ClaimPath[]
  /** Mandatory claims that are missing, while they must not be selectively disclosable (`sd: "never"`). */
  missingMandatoryClaims: ClaimPath[]
  /** Mandatory claims that are missing, but may be selectively disclosable, so they may just not have been disclosed. */
  undisclosedMandatoryClaims: ClaimPath[]
  /** Claims present in the SD-JWT VC as non-selectively-disclosable (plain JWT claims) that should be selectively disclosable according to type metadata (`sd: "always"`). */
  invalidNonSelectivelyDisclosableClaims: ClaimPath[]
  /** Claims present in the SD-JWT VC as selectively disclosable (via disclosures) that should not be selectively disclosable according to type metadata (`sd: "never"`). */
  invalidSelectivelyDisclosableClaims: ClaimPath[]
}

/**
 * Registered SD-JWT VC claims, which are not reported as extra claims unless the type metadata declares them.
 */
const REGISTERED_CLAIMS = ['iss', 'nbf', 'exp', 'iat', 'sub', 'cnf', 'vct', 'vct#integrity', 'status']

/**
 * A claim in the SD-JWT VC. Array elements use their index in the issued array.
 */
type PresentClaim = {
  path: Array<string | number>
  isSd: boolean
}

/**
 * Compares two ClaimPath objects for equality.
 */
export function claimPathsEqual(path1: ClaimPath, path2: ClaimPath): boolean {
  if (path1.length !== path2.length) return false
  return path1.every((seg, idx) => seg === path2[idx])
}

/**
 * Checks if the first `length` segments of the claim path and the present claim path match, where `null` matches any
 * array element.
 */
function segmentsMatch(claimPath: ClaimPath, presentPath: Array<string | number>, length: number): boolean {
  for (let i = 0; i < length; i++) {
    const seg = claimPath[i]
    if (seg === null ? typeof presentPath[i] !== 'number' : seg !== presentPath[i]) return false
  }
  return true
}

function claimPathMatches(claimPath: ClaimPath, presentPath: Array<string | number>): boolean {
  return claimPath.length === presentPath.length && segmentsMatch(claimPath, presentPath, claimPath.length)
}

function isArrayElementDigest(value: unknown): value is { [SD_LIST_KEY]: string } {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === 1 &&
    typeof (value as Record<string, unknown>)[SD_LIST_KEY] === 'string'
  )
}

/**
 * Collects the claims present in the packed SD-JWT payload. An object property is selectively disclosable if its
 * digest is in the object's `_sd`, and an array element if it is a `{ "...": digest }` placeholder.
 */
function collectPresentClaims(payload: Record<string, unknown>, disclosures: Record<string, Disclosure>) {
  const claims: PresentClaim[] = []

  const visit = (node: unknown, path: Array<string | number>) => {
    if (typeof node !== 'object' || node === null) return

    if (Array.isArray(node)) {
      node.forEach((element, index) => {
        if (isArrayElementDigest(element)) {
          const disclosure = disclosures[element[SD_LIST_KEY]]
          // Withheld element or decoy
          if (!disclosure) return
          claims.push({ path: [...path, index], isSd: true })
          visit(disclosure.value, [...path, index])
        } else {
          claims.push({ path: [...path, index], isSd: false })
          visit(element, [...path, index])
        }
      })
      return
    }

    const record = node as Record<string, unknown>
    for (const [key, value] of Object.entries(record)) {
      if (key === SD_DIGEST || (path.length === 0 && key === '_sd_alg')) continue
      claims.push({ path: [...path, key], isSd: false })
      visit(value, [...path, key])
    }

    const digests = Array.isArray(record[SD_DIGEST]) ? record[SD_DIGEST] : []
    for (const digest of digests) {
      const disclosure = typeof digest === 'string' ? disclosures[digest] : undefined
      // Withheld claim or decoy
      if (!disclosure || typeof disclosure.key !== 'string') continue
      claims.push({ path: [...path, disclosure.key], isSd: true })
      visit(disclosure.value, [...path, disclosure.key])
    }
  }

  visit(payload, [])
  return claims
}

function toCanonicalClaimPath(path: Array<string | number>): ClaimPath {
  return path.map((seg) => (typeof seg === 'number' ? null : seg))
}

function createClaimPathSet() {
  const paths = new Map<string, ClaimPath>()
  return {
    add: (path: ClaimPath) => paths.set(JSON.stringify(path), path),
    values: () => Array.from(paths.values()),
  }
}

/**
 * Core function to verify present claims against Type Metadata Format.
 *
 * @param typeMetadata The resolved or unmerged type metadata format
 * @param payload The (packed) payload of the SD-JWT VC
 * @param disclosures Map of digests to the disclosures of the SD-JWT VC
 */
export function verifyClaimsAgainstTypeMetadata(
  typeMetadata: ResolvedTypeMetadata | TypeMetadataFormat,
  payload: Record<string, unknown>,
  disclosures: Record<string, Disclosure>
): TypeMetadataVerificationResult {
  const format =
    'mergedTypeMetadata' in typeMetadata
      ? (typeMetadata as ResolvedTypeMetadata).mergedTypeMetadata
      : (typeMetadata as TypeMetadataFormat)
  const metadataClaims = format.claims ?? []
  const presentClaims = collectPresentClaims(payload, disclosures)

  const extraClaims = createClaimPathSet()
  const missingMandatoryClaims = createClaimPathSet()
  const undisclosedMandatoryClaims = createClaimPathSet()
  const invalidNonSelectivelyDisclosableClaims = createClaimPathSet()
  const invalidSelectivelyDisclosableClaims = createClaimPathSet()

  const hasDeclaredChildren = (claimPath: ClaimPath) =>
    metadataClaims.some(
      (mc) => mc.path.length > claimPath.length && claimPathsEqual(mc.path.slice(0, claimPath.length), claimPath)
    )

  const isCovered = (path: Array<string | number>) => {
    if (REGISTERED_CLAIMS.includes(String(path[0])) && !metadataClaims.some((mc) => mc.path[0] === path[0])) {
      return true
    }

    return metadataClaims.some(
      (mc) =>
        // Ancestors of a declared path
        (path.length < mc.path.length && segmentsMatch(mc.path, path, path.length)) ||
        // Descendants of a declared path without declared children
        (path.length > mc.path.length && segmentsMatch(mc.path, path, mc.path.length) && !hasDeclaredChildren(mc.path))
    )
  }

  for (const presentClaim of presentClaims) {
    const matchingMetadataClaims = metadataClaims.filter((mc) => claimPathMatches(mc.path, presentClaim.path))

    if (matchingMetadataClaims.length === 0) {
      if (!isCovered(presentClaim.path)) extraClaims.add(toCanonicalClaimPath(presentClaim.path))
      continue
    }

    for (const metadataClaim of matchingMetadataClaims) {
      if (metadataClaim.sd === 'always' && !presentClaim.isSd) {
        invalidNonSelectivelyDisclosableClaims.add(metadataClaim.path)
      } else if (metadataClaim.sd === 'never' && presentClaim.isSd) {
        invalidSelectivelyDisclosableClaims.add(metadataClaim.path)
      }
    }
  }

  const isPresent = (path: ClaimPath) => presentClaims.some((pc) => claimPathMatches(path, pc.path))
  for (const metadataClaim of metadataClaims) {
    if (!metadataClaim.mandatory || isPresent(metadataClaim.path)) continue

    // A claim that must not be selectively disclosable is only missing when its parent is present,
    // otherwise the holder may have withheld the parent
    const parentPath = metadataClaim.path.slice(0, -1)
    if (metadataClaim.sd === 'never' && (parentPath.length === 0 || isPresent(parentPath))) {
      missingMandatoryClaims.add(metadataClaim.path)
    } else {
      undisclosedMandatoryClaims.add(metadataClaim.path)
    }
  }

  // Only report the topmost undeclared path
  const extraClaimPaths = extraClaims.values()
  return {
    extraClaims: extraClaimPaths.filter(
      (path) =>
        !extraClaimPaths.some(
          (other) => other.length < path.length && claimPathsEqual(other, path.slice(0, other.length))
        )
    ),
    missingMandatoryClaims: missingMandatoryClaims.values(),
    undisclosedMandatoryClaims: undisclosedMandatoryClaims.values(),
    invalidNonSelectivelyDisclosableClaims: invalidNonSelectivelyDisclosableClaims.values(),
    invalidSelectivelyDisclosableClaims: invalidSelectivelyDisclosableClaims.values(),
  }
}
