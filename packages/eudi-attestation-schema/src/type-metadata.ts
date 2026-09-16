/**
 * SD-JWT VC Type Metadata.
 *
 * A `dc+sd-jwt` reference in a catalogue entry resolves to a Type Metadata document, not to a
 * bare JSON Schema. The document carries the claim set with explicit claims path pointers, the
 * disclosure policy per claim.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-18.html#name-sd-jwt-vc-type-metadata
 */

import type { Claim, TypeMetadataFormat } from '@sd-jwt/sd-jwt-vc'

export const ClaimSelectiveDisclosureValues = ['always', 'allowed', 'never'] as const

export {
  ClaimPathSchema as ClaimsPathSchema,
  ClaimSchema as TypeMetadataClaimSchema,
  ClaimSelectiveDisclosureSchema,
  TypeMetadataFormatSchema as TypeMetadataSchema,
} from '@sd-jwt/sd-jwt-vc'

export type TypeMetadataClaim = Claim
export type TypeMetadata = TypeMetadataFormat
export type { ClaimPath, ClaimSelectiveDisclosure } from '@sd-jwt/sd-jwt-vc'

/**
 * Merge an extended Type Metadata document with the one extending it. Members declared by the
 * extending document win, matching claims replace the inherited claim, and display metadata is
 * inherited when the extending document does not declare it.
 */
export function mergeTypeMetadata(parent: TypeMetadata, child: TypeMetadata): TypeMetadata {
  const merged: TypeMetadata = { ...parent, ...child }

  if (parent.claims || child.claims) {
    const childClaims = [...(child.claims ?? [])]
    const claims = (parent.claims ?? []).map((parentClaim) => {
      const index = childClaims.findIndex(
        (childClaim) =>
          childClaim.path.length === parentClaim.path.length &&
          childClaim.path.every((component, pathIndex) => component === parentClaim.path[pathIndex])
      )

      if (index === -1) return parentClaim

      return childClaims.splice(index, 1)[0]
    })

    merged.claims = [...claims, ...childClaims]
  }

  if (child.display === undefined && parent.display !== undefined) {
    merged.display = parent.display
  }

  return merged
}
