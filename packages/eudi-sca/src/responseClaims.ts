import { base64url, type Hasher } from '@owf/identity-common'
import z from 'zod'

export type CreateResponseClaimsOptions = {
  responseMode: string
  displayLocale: string
  amr: Array<AuthenticationMethodsReferences>
  transactionData: string
  transactionDataHashingAlgorithm: string
  // TODO: can we generate this?
  metadataIntegrity: string
  // TODO: can we generate this?
  requestIntegrity: string
  walletInsanceVersion: string
}

export enum AuthenticationMethodsReferences {
  Pin = 'pin',
  AlphanumericPasswordOrPassphrase = 'pwd',
  HardwareSecuredKey = 'hwk',
  SoftwareSecuredKey = 'swk',
  OneTimePassword = 'otp',
  BiometricsStrong = 'bio_strong',
  BiometricsWeak = 'bio_weak',
  Fingerprint = 'fpt',
  FacialRecognition = 'face',
  IrisScan = 'iris',
}

export const createResponseClaims = async (
  options: CreateResponseClaimsOptions,
  ctx: { hasher: Hasher; getRandomValues: (length: number) => Uint8Array }
) => {
  const transactionDataHash = await ctx.hasher(options.transactionData, options.transactionDataHashingAlgorithm)

  return {
    jti: base64url.encode(ctx.getRandomValues(128 / 8)),
    response_mode: options.responseMode,
    display_locale: options.displayLocale,
    amr: z.array(z.enum(AuthenticationMethodsReferences)).min(2).parse(options.amr),
    transaction_data_hash: transactionDataHash,
    transaction_data_hash_alg: options.transactionDataHashingAlgorithm,
    metadata_integrity: options.metadataIntegrity,
    request_integrity: options.requestIntegrity,
    walletInstanceVersion: options.walletInsanceVersion,
  }
}
