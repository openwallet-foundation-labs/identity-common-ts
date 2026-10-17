import type { DeviceRequestMatchResult } from '../utils/matchDeviceRequest.js'
import { VerificationError } from './errors.js'

/**
 * The structured result of a check that has more to report than a reason string, discriminated by
 * `type`. A check that produces one attaches it to its {@link VerificationAssessment}, so that it
 * reaches both a callback that collects the checks and the {@link VerificationError} the default
 * callback throws.
 */
export type VerificationAssessmentResult =
  | {
      type: 'deviceRequestMatch'
      match: DeviceRequestMatchResult
    }
  | {
      /** The status of the MSO in its status list is not Valid. */
      type: 'statusListEntryNotValid'
      uri: string
      idx: number
      /** The status at `idx`, e.g. `1` for Invalid (revoked) or `2` for Suspended. */
      status: number
    }
  | {
      /** The identifier of the MSO is in its identifier list. */
      type: 'identifierListEntryRevoked'
      uri: string
      id: Uint8Array
    }

export interface VerificationAssessment {
  status: 'PASSED' | 'FAILED' | 'WARNING'
  category: 'DOCUMENT_FORMAT' | 'DEVICE_AUTH' | 'ISSUER_AUTH' | 'DATA_INTEGRITY' | 'READER_AUTH'
  check: string
  reason?: string
  /**
   * The structured result of the check, for the checks that produce one.
   */
  result?: VerificationAssessmentResult
}

export type VerificationCallback = (item: VerificationAssessment) => void

export const defaultVerificationCallback: VerificationCallback = (verification) => {
  if (verification.status !== 'FAILED') return
  throw new VerificationError(verification.reason ?? verification.check, verification)
}

export const onCategoryCheck = (onCheck: VerificationCallback, category: VerificationAssessment['category']) => {
  return (item: Omit<VerificationAssessment, 'category'>) => {
    onCheck({ ...item, category })
  }
}
