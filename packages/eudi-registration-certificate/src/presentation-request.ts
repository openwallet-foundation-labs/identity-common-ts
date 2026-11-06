/**
 * Registration certificates in presentation requests: ISO/IEC 18013-5 mdoc requests (ETSI TS 119 472-2 V1.3.1 clause
 * 5.3.2) and OpenID4VP requests (clause 6.3.2.2), both as amended by Annex 2 of CIR (EU) 2024/2982.
 */

import { base64url, bytesToString, stringToBytes } from '@owf/identity-common'
import { decodeRegistrationCertificateCwt } from './cwt'
import { decodeRegistrationCertificateJwt } from './signer'
import type { SignedRegistrationCertificateCwt, SignedRegistrationCertificateJwt } from './types'
import { validationError } from './validator'

/** Label of the registration certificate in the `requestInfo` of an `ItemsRequest` (ISO/IEC 18013-5-REQ-06) */
const MDOC_REGISTRATION_CERTIFICATE_KEY = 'euWrprc'

/** `format` of the `verifier_info` element with the registration certificate (OIDFVP-HAIP-COMMON-REQ-RO-15) */
const OPENID4VP_REGISTRATION_CERTIFICATE_FORMAT = 'registration_cert'

/**
 * The `requestInfo` entry that carries a registration certificate in an mdoc request, to spread into the `extensions` of
 * the `requestInfo` of an `ItemsRequest` of `@owf/mdoc`
 *
 * @param registrationCertificate - A CWT, which CIR (EU) 2024/2982 asks for, or a compact JWS
 */
export function mdocRegistrationCertificateExtension(registrationCertificate: Uint8Array | string): {
  euWrprc: Uint8Array
} {
  return {
    [MDOC_REGISTRATION_CERTIFICATE_KEY]:
      typeof registrationCertificate === 'string' ? stringToBytes(registrationCertificate) : registrationCertificate,
  }
}

/** Options for {@link openid4vpRegistrationCertificateVerifierInfo} */
export interface Openid4vpRegistrationCertificateVerifierInfoOptions {
  /**
   * How `data` carries the JWT: `base64url` encoded, as OIDFVP-HAIP-COMMON-REQ-RO-16 asks, or as the `compact`
   * serialization itself
   *
   * @default 'base64url'
   */
  encoding?: 'base64url' | 'compact'
}

/**
 * The `verifier_info` element that carries a registration certificate in an OpenID4VP request. Only a JWT, as a CWT is
 * for mdoc requests.
 *
 * @param registrationCertificate - A compact JWS
 */
export function openid4vpRegistrationCertificateVerifierInfo(
  registrationCertificate: string,
  { encoding = 'base64url' }: Openid4vpRegistrationCertificateVerifierInfoOptions = {}
): { format: 'registration_cert'; data: string } {
  return {
    format: OPENID4VP_REGISTRATION_CERTIFICATE_FORMAT,
    data: encoding === 'compact' ? registrationCertificate : base64url.encode(stringToBytes(registrationCertificate)),
  }
}

/**
 * Decode the registration certificate an mdoc reader sends in the `requestInfo` of an `ItemsRequest`, without
 * cryptographic verification.
 *
 * CIR (EU) 2024/2982 asks for a CBOR-encoded registration certificate, which is a CWT. A JWT, the other format of
 * GEN-5.2.1-01, is accepted too.
 *
 * @param requestInfo - The `requestInfo` of an `ItemsRequest` of `@owf/mdoc`
 * @returns The decoded registration certificate, or `undefined` when the request info has none
 * @throws RegistrationCertificateValidationError if the registration certificate is not a valid one
 */
export function decodeMdocRegistrationCertificate(
  requestInfo: { getExtension(key: string): unknown } | undefined,
  accessCertificateSub: string
): SignedRegistrationCertificateJwt | SignedRegistrationCertificateCwt | undefined {
  // The CDDL of ETSI TS 119 472-2 spells the label `eUWrprc`, its requirements and the CIR `euWrprc`
  const value = requestInfo?.getExtension(MDOC_REGISTRATION_CERTIFICATE_KEY) ?? requestInfo?.getExtension('eUWrprc')
  if (value === undefined) return undefined

  if (!(value instanceof Uint8Array)) {
    throw validationError('Invalid registration certificate in the mdoc request', {
      code: 'invalid_type',
      path: [MDOC_REGISTRATION_CERTIFICATE_KEY],
      message: `${MDOC_REGISTRATION_CERTIFICATE_KEY} must be a byte string`,
      requirement: 'ISO/IEC 18013-5-REQ-05',
      context: { expected: 'bstr' },
    })
  }

  return decodeSerializedRegistrationCertificate(value, accessCertificateSub)
}

/**
 * Decode the registration certificate a verifier sends in the `verifier_info` of an OpenID4VP request, without
 * cryptographic verification. Only a JWT is accepted, as a CWT is for mdoc requests.
 *
 * OIDFVP-HAIP-COMMON-REQ-RO-16 has `data` be the base64url encoding of the serialized registration certificate. The
 * compact serialization itself is accepted too.
 *
 * @param verifierInfo - The `verifier_info` of the request
 * @returns The decoded registration certificate, or `undefined` when `verifier_info` has none
 * @throws RegistrationCertificateValidationError if the element or the registration certificate is not valid
 */
export function decodeOpenid4vpRegistrationCertificate(
  verifierInfo: ReadonlyArray<{ format: string; data: unknown; credential_ids?: unknown }> | undefined,
  accessCertificateSub: string
): SignedRegistrationCertificateJwt | undefined {
  const index = verifierInfo?.findIndex(({ format }) => format === OPENID4VP_REGISTRATION_CERTIFICATE_FORMAT) ?? -1
  if (!verifierInfo || index === -1) return undefined

  const message = 'Invalid registration certificate in verifier_info'
  // The EUDI ARF (RPRC_19) has a request carry a single registration certificate, and with more it is unclear which applies
  if (verifierInfo.filter(({ format }) => format === OPENID4VP_REGISTRATION_CERTIFICATE_FORMAT).length > 1) {
    throw validationError(message, {
      code: 'invalid_value',
      message: 'verifier_info has more than one registration certificate',
      requirement: 'RPRC_19',
    })
  }

  const { data, credential_ids } = verifierInfo[index]
  if (credential_ids !== undefined) {
    throw validationError(message, {
      code: 'not_allowed',
      path: [index, 'credential_ids'],
      message: 'The registration certificate must not have credential_ids',
      requirement: 'OIDFVP-HAIP-COMMON-REQ-RO-14',
    })
  }
  if (typeof data !== 'string') {
    throw validationError(message, {
      code: 'invalid_type',
      path: [index, 'data'],
      message: 'The registration certificate must be a string',
      requirement: 'OIDFVP-HAIP-COMMON-REQ-RO-16',
      context: { expected: 'string' },
    })
  }

  // A base64url string has no dots, a compact JWS has two
  if (data.includes('.')) return decodeRegistrationCertificateJwt(data, accessCertificateSub)

  let bytes: Uint8Array
  try {
    bytes = base64url.decode(data)
  } catch {
    throw validationError(message, {
      code: 'invalid_format',
      path: [index, 'data'],
      message: 'The registration certificate is not base64url',
      requirement: 'OIDFVP-HAIP-COMMON-REQ-RO-16',
      context: { format: 'base64url' },
    })
  }
  return decodeRegistrationCertificateJwt(bytesToString(bytes), accessCertificateSub)
}

/** Decode a serialized registration certificate of either format of GEN-5.2.1-01 */
function decodeSerializedRegistrationCertificate(
  bytes: Uint8Array,
  accessCertificateSub: string
): SignedRegistrationCertificateJwt | SignedRegistrationCertificateCwt {
  // A COSE_Sign1 starts with its tag (0xd2) or as an array of four (0x84), a compact JWS with base64url text
  return bytes[0] === 0xd2 || bytes[0] === 0x84
    ? decodeRegistrationCertificateCwt(bytes, accessCertificateSub)
    : decodeRegistrationCertificateJwt(bytesToString(bytes), accessCertificateSub)
}
