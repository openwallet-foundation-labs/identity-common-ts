import type { InferOutputUnion, Simplify } from '@openid4vc/utils'
import { addValidationIssue, unionParams, zNonEmptyString, zodErrorMap } from '@owf/identity-common'
import z from 'zod'
import {
  zJwtVcJsonCredentialRequestFormatDraft14,
  zJwtVcJsonLdCredentialRequestFormatDraft14,
  zLdpVcCredentialRequestFormatDraft14,
  zLegacySdJwtVcCredentialRequestFormatDraft14,
  zMsoMdocCredentialRequestFormatDraft14,
} from '../formats/credential'
import {
  zJwtVcJsonCredentialRequestDraft11To14,
  zJwtVcJsonCredentialRequestDraft14To11,
  zJwtVcJsonFormatIdentifier,
} from '../formats/credential/w3c-vc/z-w3c-jwt-vc-json'
import {
  zJwtVcJsonLdCredentialRequestDraft11To14,
  zJwtVcJsonLdCredentialRequestDraft14To11,
  zJwtVcJsonLdFormatIdentifier,
} from '../formats/credential/w3c-vc/z-w3c-jwt-vc-json-ld'
import {
  zLdpVcCredentialRequestDraft11To14,
  zLdpVcCredentialRequestDraft14To11,
  zLdpVcFormatIdentifier,
} from '../formats/credential/w3c-vc/z-w3c-ldp-vc'
import { zSdJwtW3VcCredentialRequestFormatDraft14 } from '../formats/credential/w3c-vc/z-w3c-sd-jwt-vc'
import { zCredentialRequestCommon, zCredentialResponseEncryption } from './z-credential-request-common'

export const allCredentialRequestFormats = [
  zSdJwtW3VcCredentialRequestFormatDraft14,
  zMsoMdocCredentialRequestFormatDraft14,
  zLdpVcCredentialRequestFormatDraft14,
  zJwtVcJsonLdCredentialRequestFormatDraft14,
  zJwtVcJsonCredentialRequestFormatDraft14,
  zLegacySdJwtVcCredentialRequestFormatDraft14,
] as const

// The issues of a nested parse are passed on as they are. Parse like `parseWithSchema`, so they
// have its messages and the input that tells a `missing_value` from an `invalid_type`.
const nestedParseParams = { reportInput: true, error: zodErrorMap }

export const allCredentialRequestFormatIdentifiers = allCredentialRequestFormats.map(
  (format) => format.shape.format.value
)

// Credential configuration no format used
const zCredentialRequestCredentialConfigurationId = z.object({
  credential_configuration_id: zNonEmptyString,

  credential_identifier: z
    .never({ message: "'credential_identifier' cannot be defined when 'credential_configuration_id' is set." })
    .optional(),
})

// Authorization details no format used
const zAuthorizationDetailsCredentialRequest = z.object({
  credential_identifier: zNonEmptyString,

  credential_configuration_id: z
    .never({ message: "'credential_configuration_id' cannot be defined when 'credential_identifier' is set." })
    .optional(),
})

const zCredentialRequestFormat = z
  .object({
    format: zNonEmptyString,

    // We add these nevers here so that if one of these is present, we will always use
    // the new properties rather than the deprecated format
    credential_identifier: z
      .never({ message: "'credential_identifier' cannot be defined when 'format' is set." })
      .optional(),

    credential_configuration_id: z
      .never({ message: "'credential_configuration_id' cannot be defined when 'format' is set." })
      .optional(),
  })
  .loose()

export const zCredentialRequestDraft14WithFormat = zCredentialRequestCommon
  .and(zCredentialRequestFormat)
  .transform((data, ctx) => {
    // No additional validation for unknown formats
    if (
      !allCredentialRequestFormatIdentifiers.includes(
        data.format as (typeof allCredentialRequestFormatIdentifiers)[number]
      )
    )
      return data

    const result = z
      // We use object and passthrough as otherwise the non-format specific properties will be stripped
      .object({})
      .loose()
      // FIXME(vc+sd-jwt): use discriminated union when dropping support for legacy vc+sd-jwt format.
      .and(z.union(allCredentialRequestFormats))
      .safeParse(data, nestedParseParams)
    if (result.success) {
      return result.data as Simplify<typeof result.data & typeof data>
    }
    for (const issue of result.error.issues) ctx.addIssue({ ...issue })
    return z.NEVER
  })

const zCredentialRequestDraft15 = z.union([
  zCredentialRequestCommon.and(zAuthorizationDetailsCredentialRequest),
  zCredentialRequestCommon.and(zCredentialRequestCredentialConfigurationId),
])

const zCredentialRequestDraft14 = z.union([
  zCredentialRequestDraft14WithFormat,
  zCredentialRequestCommon.and(zAuthorizationDetailsCredentialRequest),
])

export const zCredentialRequestDraft11To14 = zCredentialRequestCommon
  .and(zCredentialRequestFormat)
  .transform((data, ctx): unknown => {
    const formatSpecificTransformations = {
      [zLdpVcFormatIdentifier.value]: zLdpVcCredentialRequestDraft11To14,
      [zJwtVcJsonFormatIdentifier.value]: zJwtVcJsonCredentialRequestDraft11To14,
      [zJwtVcJsonLdFormatIdentifier.value]: zJwtVcJsonLdCredentialRequestDraft11To14,
    } as const

    if (!Object.keys(formatSpecificTransformations).includes(data.format)) return data

    const schema = formatSpecificTransformations[data.format as keyof typeof formatSpecificTransformations]
    const result = schema.safeParse(data, nestedParseParams)
    if (result.success) return result.data
    for (const issue of result.error.issues) ctx.addIssue({ ...issue })
    return z.NEVER
  })
  .pipe(zCredentialRequestDraft14)

export const zCredentialRequestDraft14To11 = zCredentialRequestDraft14.transform((data, ctx) => {
  if (data.credential_identifier !== undefined) {
    addValidationIssue(ctx, {
      code: 'not_allowed',
      message: `'credential_identifier' is not supported in OpenID4VCI draft 11`,
      path: ['credential_identifier'],
    })
    return z.NEVER
  }
  const formatSpecificTransformations = {
    [zLdpVcFormatIdentifier.value]: zLdpVcCredentialRequestDraft14To11,
    [zJwtVcJsonFormatIdentifier.value]: zJwtVcJsonCredentialRequestDraft14To11,
    [zJwtVcJsonLdFormatIdentifier.value]: zJwtVcJsonLdCredentialRequestDraft14To11,
  } as const

  if (!Object.keys(formatSpecificTransformations).includes(data.format)) return data

  const schema = formatSpecificTransformations[data.format as keyof typeof formatSpecificTransformations]
  const result = schema.safeParse(data, nestedParseParams)
  if (result.success) return result.data
  for (const issue of result.error.issues) ctx.addIssue({ ...issue })
  return z.NEVER
})

export const zCredentialRequest = z.union(
  [zCredentialRequestDraft15, zCredentialRequestDraft14, zCredentialRequestDraft11To14],
  unionParams('Invalid credential request', [
    'OpenID4VCI 1.0 or draft 15',
    'OpenID4VCI draft 14',
    'OpenID4VCI draft 11',
  ])
)

export const zDeferredCredentialRequest = z.object({
  transaction_id: zNonEmptyString,
  credential_response_encryption: zCredentialResponseEncryption.optional(),
})

type CredentialRequestCommon = z.infer<typeof zCredentialRequestCommon>
export type CredentialRequestFormatSpecific = InferOutputUnion<typeof allCredentialRequestFormats>
export type CredentialRequestWithFormats = CredentialRequestCommon & CredentialRequestFormatSpecific

export type CredentialRequestDraft14 = z.infer<typeof zCredentialRequestDraft14>
export type CredentialRequestDraft15 = z.infer<typeof zCredentialRequestDraft15>
export type CredentialRequest = CredentialRequestDraft14 | CredentialRequestDraft15

export type DeferredCredentialRequest = z.infer<typeof zDeferredCredentialRequest>
