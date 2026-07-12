import { type CredentialIssuerMetadata, zCredentialIssuerMetadataSchema } from '@openid4vc/openid4vci'
import { base64url, decodeJwt } from '@owf/identity-common'
import z from 'zod'
import type { JwtSignatureVerifier } from './crypto'
import type { IssuerMetadataWithCredentialMetadataUri } from './issuerMetadata'

export enum ValueType {
  Boolean = 'boolean',
  Frequency = 'frequency',
  Image = 'image',
  IsoDate = 'iso_date',
  IsoTime = 'iso_time',
  IsoDateTime = 'iso_date_time',
  IsoCurrency = 'iso_currency',
  IsoCurrencyAmount = 'iso_currency_amount',
  LabelOnly = 'label_only',
  MiniMarkdown = 'mini_markdown',
  Url = 'url',
}

const valueTypeValues = Object.values(ValueType).join('|')
const valueTypeRegex = new RegExp(`^template:(${valueTypeValues})$`)
const urnRegex = /^urn:eudi:sca:[^:]+:[^:]+(:[^:]+)*:[^:]+$/

const CredentialMetadataDisplaySchema = z
  .array(
    z.object({
      locale: z.string().optional(),
      name: z.string(),
      display_type: z.union([z.enum(ValueType), z.string().regex(valueTypeRegex)]).optional(),
    })
  )
  .min(1)

export type CredentialMetadataDisplay = z.infer<typeof CredentialMetadataDisplaySchema>

export const CredentialMetadataClaimsDataTypeSchema = z
  .object({
    claims: z.array(
      z
        .object({
          path: z.array(z.union([z.string(), z.null()])),
          mandatory: z.boolean().optional(),
          display: CredentialMetadataDisplaySchema.optional(),
          value_type: z.union([z.enum(ValueType), z.string()]).optional(),
        })
        .superRefine((val, ctx) => {
          if (!val.display && val.value_type !== undefined) {
            ctx.addIssue({
              code: 'custom',
              message: 'value_type must not be used on claims without a display array',
              path: ['value_type'],
            })
          }
        })
    ),
    ui_labels: z.unknown(),
  })
  .catchall(z.unknown())

export type CredentialMetadataClaimsDataType = z.infer<typeof CredentialMetadataClaimsDataTypeSchema>

const CredentialMetadataSchema = z.object({
  transaction_data_types: z.record(z.string().regex(urnRegex), CredentialMetadataClaimsDataTypeSchema),
})

export type CredentialMetadata = z.infer<typeof CredentialMetadataSchema>

export const parseCredentialMetadata = (credentialMetadata: Record<string, unknown>) => {
  const cm = CredentialMetadataSchema.parse(credentialMetadata)
  return cm
}

export async function fetchCredentialMetadata(
  verifier: JwtSignatureVerifier,
  credentialMetadataSource: string | IssuerMetadataWithCredentialMetadataUri,
  customFetcher = fetch,
  langCode?: string
): Promise<CredentialMetadata & CredentialIssuerMetadata> {
  const uri =
    typeof credentialMetadataSource === 'string'
      ? credentialMetadataSource
      : credentialMetadataSource.credential_metadata_uri
  if (!uri) {
    throw Error('credential_metadata_uri is not defined on the issuer metadata')
  }

  const response = await customFetcher(uri, {
    headers: {
      Accept: 'application/jwt',
      ...(langCode ? { 'Accept-Language': langCode } : {}),
    },
  })

  const payload = await validateJwt(await response.text(), uri, verifier)

  return CredentialMetadataSchema.extend(zCredentialIssuerMetadataSchema.shape).parse(payload.credential_metadata)
}

/**
 *
 * @todo validate the sub, iss, x5c chain
 *
 */
const validateJwt = async (jwt: string, credentialMetadataUri: string, verifier: JwtSignatureVerifier) => {
  const { header: h, payload: p, signature } = decodeJwt(jwt)
  const [headerString, payloadString] = jwt.split('.')

  const header = z.object({ x5c: z.array(z.string()), typ: z.literal('credential-metadata+jwt') }).parse(h)
  const payload = z
    .object({
      iss: z.string(),
      sub: z.string().min(1, { message: 'sub must be a non-empty credential type identifier' }),
      format: z.enum(['dc+sd-jwt', 'mso_mdoc'], {
        message: 'format must be a valid OID4VCI credential format identifier',
      }),
      iat: z.number().int().positive({ message: 'iat must be a positive Unix timestamp' }),
      exp: z.number().int().positive({ message: 'exp must be a positive Unix timestamp' }),
      credential_metadata_uri: z.url({ message: 'credential_metadata_uri must be a valid URL' }),
      credential_metadata: zCredentialIssuerMetadataSchema,
    })
    .refine((data) => data.exp > data.iat, { message: 'exp must be after iat', path: ['exp'] })
    .refine((data) => new Date(data.exp) < new Date(), { message: 'exp must be after iat', path: ['exp'] })
    .refine(
      (data) => {
        return data.credential_metadata_uri === credentialMetadataUri
      },
      {
        message: `credential_metadata_uri '${p.credential_metadata_uri}'  must match source '${credentialMetadataUri}'`,
        path: ['credential_metadata_uri'],
      }
    )
    .parse(p)

  const toBeVerified = `${headerString}.${payloadString}`

  await verifier(header.x5c, toBeVerified, base64url.decode(signature))

  return payload
}
