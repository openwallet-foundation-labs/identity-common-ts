import { decodeJwt } from '@owf/identity-common'
import { validateStatusListJwt } from '@owf/token-status-list'
import { type DocumentInput, errorMessage, JWS, toText } from './input'
import { type Inspection, InspectionError } from './inspection'
import { jwsSignatureCheck } from './signature'

export interface StatusListOptions {
  /** The uri of the status list reference, which sub has to equal */
  uri?: string
  /** The key or certificates of the signer */
  key?: string
}

// Status values of draft-ietf-oauth-status-list-16 Section 7.1
function statusName(status: number): string {
  const hex = `0x${status.toString(16).padStart(2, '0')}`
  if (status === 0) return `Valid (${hex})`
  if (status === 1) return `Invalid (${hex})`
  if (status === 2) return `Suspended (${hex})`
  if (status === 3 || (status >= 0x0c && status <= 0x0f)) return `Application specific (${hex})`
  return `Reserved (${hex})`
}

/** Parse a Token Status List JWT, check its header and claims, and count its statuses */
export function inspectStatusList(input: DocumentInput, options: StatusListOptions = {}): Inspection {
  const jws = toText(input)
  if (!jws) throw new InspectionError('There is nothing to inspect')
  if (!JWS.test(jws)) throw new InspectionError('A status list is read as JWT, and this is not one')
  let header: Record<string, unknown>
  let payload: Record<string, unknown>
  try {
    ;({ header, payload } = decodeJwt<Record<string, unknown>, Record<string, unknown>>(jws))
  } catch (error) {
    throw new InspectionError(`The JWT cannot be decoded: ${errorMessage(error)}`)
  }

  const uri = options.uri?.trim() || undefined
  const { findings, statusList } = validateStatusListJwt(header, payload, { uri })
  const inspection: Inspection = {
    kind: 'status-list',
    title: 'Token Status List (JWT)',
    checks: [
      'draft-ietf-oauth-status-list-16 header and claims',
      ...(uri ? ['sub against the uri of the reference'] : []),
    ],
    notes: uri ? [] : ['sub is not compared with the uri of a referenced token: give the uri to do so'],
    value: { header, payload },
    findings,
    signatures: [jwsSignatureCheck(jws, header, options.key)],
  }
  if (!statusList) return inspection

  const total = statusList.totalStatuses
  const counts = new Map<number, number>()
  for (const status of statusList.statusList) counts.set(status, (counts.get(status) ?? 0) + 1)
  inspection.facts = [
    // The compressed list does not keep its length, so it is padded to whole bytes
    ['Entries', `${total.toLocaleString('en')} of ${statusList.getBitsPerStatus()} bits, padded to whole bytes`],
    [
      'Statuses',
      [...counts]
        .sort(([a], [b]) => a - b)
        .map(([status, count]) => `${statusName(status)}: ${count.toLocaleString('en')}`)
        .join(', '),
    ],
  ]
  inspection.lookup = {
    label: 'Status at index',
    placeholder: `0 to ${total - 1}`,
    find: (input) => {
      const index = Number(input)
      if (input.trim() === '' || !Number.isInteger(index) || index < 0 || index >= total) {
        return `The index must be a whole number from 0 to ${total - 1}`
      }
      return statusName(statusList.getStatus(index))
    },
  }
  return inspection
}
