import { parseCertificate } from '@owf/crypto'
import { base64urlEncode } from '@owf/identity-common'
import type { ListAndSchemeInformation, LoTE, LoTEDocument, SignedLoTE, SignOptions, TrustedEntity } from './types'

/**
 * Sign a LoTE document
 *
 * @param options - Signing options including LoTE document, key ID, and signer function
 * @returns The signed LoTE document as a JWS
 *
 * @example Using a local key via @owf/crypto:
 * ```typescript
 * import { ES256 } from '@owf/crypto';
 * import { signLoTE } from '@owf/eudi-lote';
 *
 * const { privateKey } = await ES256.generateKeyPair();
 * const signer = await ES256.getSigner(privateKey);
 * const signed = await signLoTE({
 *   lote: myLoTE,
 *   keyId: 'lote-signer-2025',
 *   signer,
 * });
 * ```
 *
 * @example Using an external KMS:
 * ```typescript
 * const signed = await signLoTE({
 *   lote: myLoTE,
 *   keyId: 'lote-signer-2025',
 *   signer: async (data) => myKms.sign('ES256', data),
 * });
 * ```
 */
export async function signLoTE(options: SignOptions): Promise<SignedLoTE> {
  const { lote, keyId, algorithm = 'ES256', certificates, signer } = options

  const header: Record<string, unknown> = {
    alg: algorithm,
    typ: 'trustlist+jwt',
    kid: keyId,
  }

  if (certificates && certificates.length > 0) {
    header.x5c = certificates.map(parseCertificate)
  }

  const encodedHeader = base64urlEncode(JSON.stringify(header))
  const encodedPayload = base64urlEncode(JSON.stringify(lote))
  const signingInput = `${encodedHeader}.${encodedPayload}`

  const signature = await signer(signingInput)
  const jws = `${signingInput}.${signature}`

  return {
    jws,
    header: {
      alg: algorithm,
      typ: 'trustlist+jwt',
      kid: keyId,
      x5c: header.x5c as string[] | undefined,
    },
    payload: lote,
  }
}

/**
 * Create a new LoTE document with required structure
 * Per ETSI TS 119 602, only SchemeOperatorName, ListIssueDateTime and NextUpdate are required
 * Default NextUpdate is 6 months per ETSI TS 119 602 maximum validity
 */
export function createLoTE(
  schemeInfo: Partial<ListAndSchemeInformation> & Pick<ListAndSchemeInformation, 'SchemeOperatorName'>,
  entities: TrustedEntity[] = []
): LoTEDocument {
  const now = new Date()
  const sixMonthsLater = new Date(now)
  sixMonthsLater.setMonth(sixMonthsLater.getMonth() + 6)

  const info: ListAndSchemeInformation = {
    LoTEVersionIdentifier: schemeInfo.LoTEVersionIdentifier ?? 1,
    LoTESequenceNumber: schemeInfo.LoTESequenceNumber ?? 1,
    LoTEType: schemeInfo.LoTEType,
    SchemeOperatorName: schemeInfo.SchemeOperatorName,
    SchemeOperatorAddress: schemeInfo.SchemeOperatorAddress,
    SchemeName: schemeInfo.SchemeName,
    SchemeInformationURI: schemeInfo.SchemeInformationURI,
    StatusDeterminationApproach: schemeInfo.StatusDeterminationApproach,
    SchemeTypeCommunityRules: schemeInfo.SchemeTypeCommunityRules,
    SchemeTerritory: schemeInfo.SchemeTerritory,
    PolicyOrLegalNotice: schemeInfo.PolicyOrLegalNotice,
    HistoricalInformationPeriod: schemeInfo.HistoricalInformationPeriod,
    PointersToOtherLoTE: schemeInfo.PointersToOtherLoTE,
    ListIssueDateTime: schemeInfo.ListIssueDateTime ?? now.toISOString(),
    NextUpdate: schemeInfo.NextUpdate ?? sixMonthsLater.toISOString(),
    DistributionPoints: schemeInfo.DistributionPoints,
    SchemeExtensions: schemeInfo.SchemeExtensions,
  }

  const lote: LoTE = {
    // Fields not given are left out rather than written as undefined
    ListAndSchemeInformation: Object.fromEntries(
      Object.entries(info).filter(([, value]) => value !== undefined)
    ) as ListAndSchemeInformation,
    // No entities: the key is left out, as the EC lists do (the JSON schema has minItems 1)
    ...(entities.length > 0 ? { TrustedEntitiesList: entities } : {}),
  }

  return { LoTE: lote }
}

/**
 * Options for updating a LoTE version
 */
export interface UpdateLoTEVersionOptions {
  /**
   * The issue date/time for the new version.
   * Useful when generating a LoTE in advance before publication.
   * Defaults to the current time.
   */
  listIssueDateTime?: Date | string
  /**
   * The next update date/time.
   * Per ETSI TS 119 602, maximum validity is 6 months.
   * Defaults to 6 months from listIssueDateTime.
   */
  nextUpdate?: Date | string
}

/**
 * Increment the sequence number and update timestamps for a new version
 *
 * @param lote - The LoTE document to update
 * @param options - Optional settings for listIssueDateTime and nextUpdate
 * @returns A new LoTE document with incremented sequence number and updated timestamps
 *
 * @example Update with defaults (now + 6 months):
 * ```typescript
 * const updated = updateLoTEVersion(lote);
 * ```
 *
 * @example Schedule for future publication:
 * ```typescript
 * const updated = updateLoTEVersion(lote, {
 *   listIssueDateTime: new Date('2025-01-01'),
 *   nextUpdate: new Date('2025-06-01'),
 * });
 * ```
 */
export function updateLoTEVersion(lote: LoTEDocument, options: UpdateLoTEVersionOptions = {}): LoTEDocument {
  const issueDate = options.listIssueDateTime
    ? typeof options.listIssueDateTime === 'string'
      ? new Date(options.listIssueDateTime)
      : options.listIssueDateTime
    : new Date()

  const defaultNextUpdate = new Date(issueDate)
  defaultNextUpdate.setMonth(defaultNextUpdate.getMonth() + 6)

  const nextUpdateDate = options.nextUpdate
    ? typeof options.nextUpdate === 'string'
      ? options.nextUpdate
      : options.nextUpdate.toISOString()
    : defaultNextUpdate.toISOString()

  return {
    LoTE: {
      ...lote.LoTE,
      ListAndSchemeInformation: {
        ...lote.LoTE.ListAndSchemeInformation,
        LoTESequenceNumber: lote.LoTE.ListAndSchemeInformation.LoTESequenceNumber + 1,
        ListIssueDateTime: issueDate.toISOString(),
        NextUpdate: nextUpdateDate,
      },
    },
  }
}

/**
 * Add a trusted entity to a LoTE document
 */
export function addTrustedEntity(lote: LoTEDocument, entity: TrustedEntity): LoTEDocument {
  return {
    LoTE: {
      ...lote.LoTE,
      TrustedEntitiesList: [...(lote.LoTE.TrustedEntitiesList ?? []), entity],
    },
  }
}

/**
 * Remove a trusted entity from a LoTE document by name
 */
export function removeTrustedEntity(lote: LoTEDocument, entityName: string): LoTEDocument {
  const list = lote.LoTE.TrustedEntitiesList
  const remaining = list?.filter((e) => !e.TrustedEntityInformation.TEName.some((n) => n.value === entityName))
  // Nothing removed: the document as it was, key and order included
  if (!list || !remaining || remaining.length === list.length) return { LoTE: { ...lote.LoTE } }
  if (remaining.length > 0) return { LoTE: { ...lote.LoTE, TrustedEntitiesList: remaining } }
  // No entity left: the key goes, as in createLoTE (the JSON schema has minItems 1)
  const { TrustedEntitiesList: _removed, ...rest } = lote.LoTE
  return { LoTE: rest }
}
