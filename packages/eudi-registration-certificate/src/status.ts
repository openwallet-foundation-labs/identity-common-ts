/**
 * Status of registration certificates (ETSI TS 119 475 clause 6.2.6), checked in the Token Status List the clause points
 * to for guidance.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html
 */

import {
  fetchStatusList,
  type StatusList,
  StatusListCwt,
  StatusType,
  verifyStatusListJwt,
} from '@owf/token-status-list'
import { verifyCwtSignature } from './cwt'
import type { Status, VerifyRegistrationCertificateCallbacks } from './types'
import { validationError } from './validator'

/** Options for {@link verifyRegistrationCertificateStatus} */
export interface VerifyRegistrationCertificateStatusOptions {
  /** The `status` of the registration certificate payload */
  status: Status
  /**
   * Verify the signature of the status list, which the registration certificate provider signs (REV-6.2.6.2-05). A CWT
   * status list must carry its chain in the protected `x5chain` header, as `verifyCose` gets no other key reference.
   */
  callbacks: VerifyRegistrationCertificateCallbacks
  /** The time to check the status list at; defaults to now */
  now?: Date
  /** Clock tolerance for `exp` and `iat` of the status list, in seconds; defaults to 30 */
  skewSeconds?: number
}

/**
 * Verify that the status list a registration certificate references (GEN-6.2.6.1-04) holds valid for it.
 *
 * `verifyRegistrationCertificate` calls this after the registration certificate itself verified, as the Token Status List
 * (section 8.3) checks a status only for a token that is otherwise valid. The status list token is checked as section 8.3
 * describes: its `typ`, its signature through the callbacks, its `sub` against the `uri`, its `iat` and `exp`, and the
 * status at `idx`.
 *
 * @throws RegistrationCertificateValidationError with a `revoked` issue if the status is not valid, a
 *   `status_list_unavailable` issue if the status list cannot be fetched, and an `invalid_status_list` issue if it does
 *   not verify. Paths are below `status`.
 */
export async function verifyRegistrationCertificateStatus({
  status,
  callbacks,
  now,
  skewSeconds,
}: VerifyRegistrationCertificateStatusOptions): Promise<void> {
  const { idx, uri } = status.status_list

  let token: string | Uint8Array
  try {
    token = await fetchStatusList({ uri, customFetcher: callbacks.fetch })
  } catch (error) {
    throw validationError('Could not verify the status of the registration certificate', {
      code: 'status_list_unavailable',
      path: ['status_list', 'uri'],
      message: `The status list at ${uri} cannot be fetched: ${(error as Error).message}`,
    })
  }

  let value: number
  try {
    let statusList: StatusList
    if (typeof token === 'string') {
      // Checks `typ`, the required `sub` and `iat`, and that `sub` is the uri the token was referenced by
      ;({ statusList } = await verifyStatusListJwt({
        jwt: token,
        uri,
        verifyJwsCallback: callbacks.verifyJws,
        now,
        skewSeconds,
      }))
    } else {
      // Decoding checks `typ`
      const statusListCwt = StatusListCwt.fromToken(token)
      await verifyCwtSignature(statusListCwt, callbacks.verifyCose)
      statusListCwt.verifyClaims({ uri, now, skewSeconds })
      statusList = statusListCwt.payload.statusList
    }

    value = statusList.getStatus(idx)
  } catch (error) {
    // Token Status List section 8.3: no statement about the status can be made
    throw validationError('Could not verify the status of the registration certificate', {
      code: 'invalid_status_list',
      path: ['status_list', 'uri'],
      message: `The status list at ${uri} does not verify: ${(error as Error).message}`,
    })
  }

  if (value !== StatusType.Valid) {
    throw validationError('Registration certificate is revoked', {
      code: 'revoked',
      path: ['status_list', 'idx'],
      message: `The status at index ${idx} of ${uri} is ${value}, not valid`,
      requirement: 'REV-6.2.6.2-04',
      context: { status: value },
    })
  }
}
