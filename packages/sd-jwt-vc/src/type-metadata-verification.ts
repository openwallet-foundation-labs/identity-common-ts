import { type Disclosure, SD_DIGEST, SD_LIST_KEY } from '@sd-jwt/core'
import type { Claim, ClaimPath, TypeMetadataFormat } from './sd-jwt-vc-type-metadata-format'

export type TypeMetadataVerificationResult = {
  extraClaims: ClaimPath[]
  missingMandatoryClaims: ClaimPath[]
  undisclosedMandatoryClaims: ClaimPath[]
  invalidNonSelectivelyDisclosableClaims: ClaimPath[]
  invalidSelectivelyDisclosableClaims: ClaimPath[]
}

const REGISTERED_CLAIMS = ['iss', 'nbf', 'exp', 'iat', 'sub', 'cnf', 'vct', 'vct#integrity', 'status']

type PresentClaim = {
  path: Array<string | number>
  isSd: boolean
}

export function claimPathsEqual(path1: ClaimPath, path2: ClaimPath): boolean {
  if (path1.length !== path2.length) return false
  return path1.every((seg, idx) => seg === path2[idx])
}

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

function collectPresentClaims(payload: Record<string, unknown>, disclosures: Record<string, Disclosure>) {
  const claims: PresentClaim[] = []

  const visit = (node: unknown, path: Array<string | number>) => {
    if (typeof node !== 'object' || node === null) return

    if (Array.isArray(node)) {
      node.forEach((element, index) => {
        if (isArrayElementDigest(element)) {
          const disclosure = disclosures[element[SD_LIST_KEY]]
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
      if (!disclosure || typeof disclosure.key !== 'string') continue
      claims.push({ path: [...path, disclosure.key], isSd: true })
      visit(disclosure.value, [...path, disclosure.key])
    }
  }

  visit(payload, [])
  return claims
}

type ClaimStatus = 'present' | 'missing' | 'undisclosed'

function childEntries(node: unknown, segment: string | null, disclosures: Record<string, Disclosure>) {
  const present: Array<{ index: string | number; value: unknown }> = []
  let hidden = false

  if (segment === null) {
    if (!Array.isArray(node)) return { present, hidden }
    node.forEach((element, index) => {
      if (!isArrayElementDigest(element)) {
        present.push({ index, value: element })
        return
      }
      const disclosure = disclosures[element[SD_LIST_KEY]]
      if (disclosure) present.push({ index, value: disclosure.value })
      else hidden = true
    })
    return { present, hidden }
  }

  if (typeof node !== 'object' || node === null || Array.isArray(node)) return { present, hidden }
  const record = node as Record<string, unknown>
  // biome-ignore lint/suspicious/noPrototypeBuiltins: `Object.hasOwn` is not in the ES2020 lib this package targets
  if (segment !== SD_DIGEST && Object.prototype.hasOwnProperty.call(record, segment)) {
    present.push({ index: segment, value: record[segment] })
  }

  const digests = Array.isArray(record[SD_DIGEST]) ? record[SD_DIGEST] : []
  for (const digest of digests) {
    const disclosure = typeof digest === 'string' ? disclosures[digest] : undefined
    if (!disclosure) hidden = true
    else if (disclosure.key === segment) present.push({ index: segment, value: disclosure.value })
  }
  return { present, hidden }
}

function mandatoryClaimStatus(
  claim: Claim,
  metadataClaims: Claim[],
  packedPayload: Record<string, unknown>,
  disclosures: Record<string, Disclosure>
): ClaimStatus {
  const sdOf = (length: number) =>
    metadataClaims.find((mc) => claimPathsEqual(mc.path, claim.path.slice(0, length)))?.sd

  const walk = (node: unknown, depth: number): ClaimStatus => {
    if (depth === claim.path.length) return 'present'

    const segment = claim.path[depth]
    const { present, hidden } = childEntries(node, segment, disclosures)
    let status: ClaimStatus = 'present'
    for (const child of present) {
      const childStatus = walk(child.value, depth + 1)
      if (childStatus === 'missing') return 'missing'
      if (childStatus === 'undisclosed') status = 'undisclosed'
    }

    if (segment === null) {
      if (!Array.isArray(node)) return 'missing'
      return present.length === 0 && hidden ? 'undisclosed' : status
    }
    if (present.length > 0) return status

    return hidden && sdOf(depth + 1) !== 'never' ? 'undisclosed' : 'missing'
  }

  return walk(packedPayload, 0)
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
 * Verifies the claims of an SD-JWT VC against type metadata.
 *
 * @param typeMetadata The type metadata to verify against. When it extends other type metadata, pass the merged
 * type metadata of the resolved chain.
 * @param packedPayload The payload of the SD-JWT VC as issued, with the `_sd` digests still in place. The payload
 * returned by `verify` is unpacked and cannot be used here.
 * @param disclosures The disclosures of the SD-JWT VC, keyed by their digest.
 */
export function verifyClaimsAgainstTypeMetadata(
  typeMetadata: TypeMetadataFormat,
  packedPayload: Record<string, unknown>,
  disclosures: Record<string, Disclosure>
): TypeMetadataVerificationResult {
  const metadataClaims = typeMetadata.claims ?? []
  const presentClaims = collectPresentClaims(packedPayload, disclosures)

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
        (path.length < mc.path.length && segmentsMatch(mc.path, path, path.length)) ||
        (path.length > mc.path.length && segmentsMatch(mc.path, path, mc.path.length) && !hasDeclaredChildren(mc.path))
    )
  }

  for (const presentClaim of presentClaims) {
    const matchingMetadataClaims = metadataClaims.filter((mc) => claimPathMatches(mc.path, presentClaim.path))

    if (matchingMetadataClaims.length === 0) {
      if (typeMetadata.claims && !isCovered(presentClaim.path)) extraClaims.add(toCanonicalClaimPath(presentClaim.path))
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

  for (const metadataClaim of metadataClaims) {
    if (!metadataClaim.mandatory) continue
    const status = mandatoryClaimStatus(metadataClaim, metadataClaims, packedPayload, disclosures)
    if (status === 'missing') missingMandatoryClaims.add(metadataClaim.path)
    else if (status === 'undisclosed') undisclosedMandatoryClaims.add(metadataClaim.path)
  }

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
