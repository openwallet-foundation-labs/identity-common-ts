import z from 'zod'

const zIssuerInfoEntry = z.object({
  format: z.string(),
  data: z.record(z.string(), z.unknown()).or(z.string()),
  // Inherited from the verifier_info structure referenced by ETSI TS 119 472-3.
  // The issuance profile does not define a mapping to credential_configuration_ids.
  credential_ids: z.tuple([z.string()], z.string()).optional(),
})

/**
 * An issuer attestation carried in `issuer_info`. The format determines how to
 * interpret its data, for example `registration_cert` for a registration certificate.
 */
export type IssuerInfoEntry = z.infer<typeof zIssuerInfoEntry>

/**
 * Issuer information as defined by ETSI TS 119 472-3, section 4.2.3.
 * Validates the structure without verifying attestation signatures or trust.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf
 */
export const zIssuerInfo = z.tuple([zIssuerInfoEntry], zIssuerInfoEntry)

/**
 * Non-empty issuer information published in Credential Issuer Metadata.
 */
export type IssuerInfo = z.infer<typeof zIssuerInfo>
