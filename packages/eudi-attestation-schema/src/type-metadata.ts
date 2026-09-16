/**
 * SD-JWT VC Type Metadata.
 *
 * A `dc+sd-jwt` reference in a catalogue entry resolves to a Type Metadata document, not to a
 * bare JSON Schema. The document carries the claim set with explicit claims path pointers, the
 * disclosure policy per claim, and either an embedded `schema` or a `schema_uri` reference.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-18.html#name-sd-jwt-vc-type-metadata
 */

import { z } from 'zod'
import { Sha256SriSchema } from './schemas'

export const ClaimSelectiveDisclosureValues = ['always', 'allowed', 'never'] as const

export const ClaimSelectiveDisclosureSchema = z.enum(ClaimSelectiveDisclosureValues)

const ClaimsPathComponentSchema = z.union([z.string(), z.number().int().nonnegative(), z.null()])

export const ClaimsPathSchema = z.array(ClaimsPathComponentSchema).min(1)

export const TypeMetadataClaimSchema = z.looseObject({
  path: ClaimsPathSchema,
  mandatory: z.boolean().optional(),
  sd: ClaimSelectiveDisclosureSchema.optional(),
  svg_id: z.string().min(1).optional(),
  display: z
    .array(
      z.looseObject({
        locale: z.string().min(1),
        label: z.string().min(1),
        description: z.string().optional(),
      })
    )
    .optional(),
})

export const TypeMetadataSchema = z
  .looseObject({
    vct: z.string().min(1),
    name: z.string().optional(),
    description: z.string().optional(),
    extends: z.url().optional(),
    'extends#integrity': Sha256SriSchema.optional(),
    display: z
      .array(
        z.looseObject({
          locale: z.string().min(1),
          name: z.string().min(1),
          description: z.string().optional(),
          rendering: z.record(z.string(), z.unknown()).optional(),
        })
      )
      .optional(),
    claims: z.array(TypeMetadataClaimSchema).optional(),
    schema: z.record(z.string(), z.unknown()).optional(),
    schema_uri: z.url().optional(),
    'schema_uri#integrity': Sha256SriSchema.optional(),
  })
  .superRefine((data, ctx) => {
    if (data.schema !== undefined && data.schema_uri !== undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['schema_uri'],
        message: 'schema and schema_uri are mutually exclusive',
      })
    }

    if (data['schema_uri#integrity'] !== undefined && data.schema_uri === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['schema_uri#integrity'],
        message: 'schema_uri#integrity requires schema_uri',
      })
    }

    if (data['extends#integrity'] !== undefined && data.extends === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['extends#integrity'],
        message: 'extends#integrity requires extends',
      })
    }
  })

export type ClaimSelectiveDisclosure = z.infer<typeof ClaimSelectiveDisclosureSchema>
export type TypeMetadataClaim = z.infer<typeof TypeMetadataClaimSchema>
export type TypeMetadata = z.infer<typeof TypeMetadataSchema>

/**
 * Merge an extended Type Metadata document with the one extending it. Members declared by the
 * extending document win, and claims are merged per claims path pointer so that a child can
 * refine a single inherited claim without restating the rest.
 */
export function mergeTypeMetadata(parent: TypeMetadata, child: TypeMetadata): TypeMetadata {
  const claims = new Map<string, TypeMetadataClaim>()

  for (const claim of parent.claims ?? []) {
    claims.set(JSON.stringify(claim.path), claim)
  }

  for (const claim of child.claims ?? []) {
    const key = JSON.stringify(claim.path)
    claims.set(key, { ...claims.get(key), ...claim })
  }

  const merged: TypeMetadata = { ...parent, ...child }

  if (claims.size > 0) {
    merged.claims = [...claims.values()]
  }

  // A child that carries its own schema replaces the inherited one rather than merging into it.
  if (child.schema !== undefined) {
    delete merged.schema_uri
    delete merged['schema_uri#integrity']
  } else if (child.schema_uri !== undefined) {
    delete merged.schema
  }

  return merged
}
