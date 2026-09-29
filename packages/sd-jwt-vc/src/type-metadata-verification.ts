import { encodePathSegment, SD_DECOY, SD_DIGEST, SD_LIST_KEY } from '@sd-jwt/core'
import type { ClaimPath, ResolvedTypeMetadata, TypeMetadataFormat } from './sd-jwt-vc-type-metadata-format'

export type TypeMetadataVerificationResult = {
  /** Claims present in the SD-JWT VC that are not declared in the type metadata. */
  extraClaims: ClaimPath[]
  /** Claims marked as mandatory in the type metadata that are missing from the SD-JWT VC. */
  missingMandatoryClaims: ClaimPath[]
  /** Claims present in the SD-JWT VC as non-selectively-disclosable (plain JWT claims) that should be selectively disclosable according to type metadata (`sd: "always"`). */
  invalidNonSelectivelyDisclosableClaims: ClaimPath[]
  /** Claims present in the SD-JWT VC as selectively disclosable (via disclosures) that should not be selectively disclosable according to type metadata (`sd: "never"`). */
  invalidSelectivelyDisclosableClaims: ClaimPath[]
}

export type PresentClaimInfo = {
  path: ClaimPath
  isSd: boolean
}

/**
 * Checks if a property key is an internal SD-JWT protocol field.
 */
function isInternalProtocolField(key: string): boolean {
  return key === '_sd_alg' || key === SD_DIGEST || key === SD_LIST_KEY || key === SD_DECOY
}

/**
 * Compares two ClaimPath objects for equality.
 */
export function claimPathsEqual(path1: ClaimPath, path2: ClaimPath): boolean {
  if (path1.length !== path2.length) return false
  return path1.every((seg, idx) => seg === path2[idx])
}

/**
 * Checks if a metadata ClaimPath matches a concrete path (which may have numeric array indices).
 */
export function matchClaimPath(metadataPath: ClaimPath, concretePath: (string | number | null)[]): boolean {
  if (metadataPath.length !== concretePath.length) return false
  for (let i = 0; i < metadataPath.length; i++) {
    const metaSegment = metadataPath[i]
    const concSegment = concretePath[i]

    if (metaSegment === null) {
      if (
        concSegment === null ||
        typeof concSegment === 'number' ||
        (typeof concSegment === 'string' && /^\d+$/.test(concSegment))
      ) {
        continue
      }
      return false
    }

    if (metaSegment !== concSegment) {
      return false
    }
  }
  return true
}

/**
 * Normalizes a concrete path to a canonical ClaimPath with `null` for array element wildcards.
 */
export function toCanonicalClaimPath(concretePath: (string | number | null)[]): ClaimPath {
  return concretePath.map((seg) =>
    typeof seg === 'number' || (typeof seg === 'string' && /^\d+$/.test(seg)) ? null : seg
  )
}

/**
 * Helper to add a ClaimPath to an array without duplicates.
 */
function addUniqueClaimPath(list: ClaimPath[], pathToAdd: ClaimPath): void {
  if (!list.some((existing) => claimPathsEqual(existing, pathToAdd))) {
    list.push(pathToAdd)
  }
}

/**
 * Extracts all present claims and their selective disclosure status from an unpacked SD-JWT payload.
 *
 * @param unpackedObj The fully unpacked JSON payload object
 * @param disclosureKeymap Map of path strings to disclosure hashes (from `@sd-jwt/core` unpack)
 */
export function extractPresentClaims(
  unpackedObj: unknown,
  disclosureKeymap: Record<string, string>
): PresentClaimInfo[] {
  const claimsMap = new Map<string, PresentClaimInfo>()

  function traverse(node: unknown, concreteSegments: (string | number)[], isAncestralSd: boolean) {
    if (concreteSegments.length > 0) {
      const encodedPathString = concreteSegments.map((seg) => encodePathSegment(String(seg))).join('.')

      const isNodeSd = isAncestralSd || Boolean(disclosureKeymap[encodedPathString])
      const canonicalPath = toCanonicalClaimPath(concreteSegments)
      const canonicalKey = JSON.stringify(canonicalPath)

      const existing = claimsMap.get(canonicalKey)
      if (existing) {
        if (isNodeSd) {
          existing.isSd = true
        }
      } else {
        claimsMap.set(canonicalKey, { path: canonicalPath, isSd: isNodeSd })
      }

      if (typeof node === 'object' && node !== null) {
        if (Array.isArray(node)) {
          node.forEach((item, index) => {
            traverse(item, [...concreteSegments, index], isNodeSd)
          })
        } else {
          for (const [key, value] of Object.entries(node)) {
            if (!isInternalProtocolField(key)) {
              traverse(value, [...concreteSegments, key], isNodeSd)
            }
          }
        }
      }
    } else {
      if (typeof node === 'object' && node !== null && !Array.isArray(node)) {
        for (const [key, value] of Object.entries(node)) {
          if (!isInternalProtocolField(key)) {
            traverse(value, [key], false)
          }
        }
      }
    }
  }

  traverse(unpackedObj, [], false)
  return Array.from(claimsMap.values())
}

/**
 * Core function to verify present claims against Type Metadata Format.
 *
 * @param typeMetadata The resolved or unmerged type metadata format
 * @param unpackedObj Unpacked SD-JWT payload object
 * @param disclosureKeymap Map of path strings to disclosure hashes
 */
export function verifyClaimsAgainstTypeMetadata(
  typeMetadata: ResolvedTypeMetadata | TypeMetadataFormat,
  unpackedObj: unknown,
  disclosureKeymap: Record<string, string>
): TypeMetadataVerificationResult {
  const format: TypeMetadataFormat =
    typeof typeMetadata === 'object' && typeMetadata !== null && 'mergedTypeMetadata' in typeMetadata
      ? (typeMetadata as ResolvedTypeMetadata).mergedTypeMetadata
      : (typeMetadata as TypeMetadataFormat)

  const result: TypeMetadataVerificationResult = {
    extraClaims: [],
    missingMandatoryClaims: [],
    invalidNonSelectivelyDisclosableClaims: [],
    invalidSelectivelyDisclosableClaims: [],
  }

  const metadataClaims = format.claims ?? []
  const presentClaims = extractPresentClaims(unpackedObj, disclosureKeymap)

  for (const presentClaim of presentClaims) {
    const matchingMetadataClaim = metadataClaims.find((mc) => matchClaimPath(mc.path, presentClaim.path))

    if (!matchingMetadataClaim) {
      addUniqueClaimPath(result.extraClaims, presentClaim.path)
    } else {
      if (matchingMetadataClaim.sd === 'always' && !presentClaim.isSd) {
        addUniqueClaimPath(result.invalidNonSelectivelyDisclosableClaims, presentClaim.path)
      } else if (matchingMetadataClaim.sd === 'never' && presentClaim.isSd) {
        addUniqueClaimPath(result.invalidSelectivelyDisclosableClaims, presentClaim.path)
      }
    }
  }

  for (const metadataClaim of metadataClaims) {
    if (metadataClaim.mandatory) {
      const isPresent = presentClaims.some((pc) => matchClaimPath(metadataClaim.path, pc.path))
      if (!isPresent) {
        addUniqueClaimPath(result.missingMandatoryClaims, metadataClaim.path)
      }
    }
  }

  return result
}
