import type { VerificationCallback } from '../mdoc/check-callback'
import type { DataElementIdentifier } from '../mdoc/models/data-element-identifier'
import type { DataElementValue } from '../mdoc/models/data-element-value'
import type { DeviceRequest } from '../mdoc/models/device-request'
import type { ItemsRequest } from '../mdoc/models/items-request'
import type { Namespace } from '../mdoc/models/namespace'

/**
 * ISO/IEC 18013-5 7.2.5: `NN` is always two digits, from `00` to `99`.
 */
const ageOverIdentifierPattern = /^age_over_(\d{2})$/
const maximumAgeOverRequests = 2

export type AgeOverCandidate = {
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
}

/**
 * The `NN` of an `age_over_NN` element identifier, or `undefined` when the identifier is not an
 * age attestation. `NN` must be exactly two digits, so `age_over_8`, `age_over_018` and
 * `age_over_18a` are not age attestations.
 */
export const parseAgeOverIdentifier = (elementIdentifier: DataElementIdentifier): number | undefined => {
  const match = ageOverIdentifierPattern.exec(elementIdentifier)
  return match ? Number(match[1]) : undefined
}

/**
 * Find the `age_over_MM` attestation that answers a request for `age_over_NN`.
 *
 * ISO/IEC 18013-5 7.2.5 lets the mdoc answer with a different age attestation than the one
 * requested: the nearest one that is `true` for `MM >= NN`, and otherwise the nearest one that is
 * `false` for `MM <= NN`.
 */
export const findAgeOverCandidate = <Candidate extends AgeOverCandidate>(
  requestedElementIdentifier: DataElementIdentifier,
  candidates: Array<Candidate>
): Candidate | undefined => {
  const requestedNn = parseAgeOverIdentifier(requestedElementIdentifier)
  if (requestedNn === undefined) return undefined

  const ageOverCandidates = candidates.flatMap((candidate) => {
    const nn = parseAgeOverIdentifier(candidate.elementIdentifier)
    return nn === undefined ? [] : [{ nn, candidate }]
  })

  const nearestTrue = ageOverCandidates
    .filter(({ nn, candidate }) => candidate.elementValue === true && nn >= requestedNn)
    .sort((a, b) => a.nn - b.nn)[0]
  if (nearestTrue) return nearestTrue.candidate

  const nearestFalse = ageOverCandidates
    .filter(({ nn, candidate }) => candidate.elementValue === false && nn <= requestedNn)
    .sort((a, b) => b.nn - a.nn)[0]

  return nearestFalse?.candidate
}

/**
 * The namespaces with more than two distinct `age_over_NN` element identifiers, with those
 * identifiers.
 *
 * ISO/IEC 18013-5 7.2.5: "an mDL reader shall not request more than two age_over_NN data elements".
 * Counted per namespace, as an age attestation only answers requests in its own namespace.
 */
export const findAgeOverLimitViolations = (
  namespaces: Iterable<readonly [Namespace, Iterable<DataElementIdentifier>]>
): Array<AgeOverLimitViolation> =>
  Array.from(namespaces, ([namespace, elementIdentifiers]) => ({
    namespace,
    ageOverIdentifiers: Array.from(new Set(elementIdentifiers)).filter(
      (elementIdentifier) => parseAgeOverIdentifier(elementIdentifier) !== undefined
    ),
  })).filter(({ ageOverIdentifiers }) => ageOverIdentifiers.length > maximumAgeOverRequests)

export type AgeOverLimitViolation = {
  namespace: Namespace
  ageOverIdentifiers: Array<DataElementIdentifier>
}

/**
 * {@link findAgeOverLimitViolations} for the namespaces of an `ItemsRequest`.
 */
export const findAgeOverRequestLimitViolations = (namespaces: ItemsRequest['namespaces']) =>
  findAgeOverLimitViolations(Array.from(namespaces, ([namespace, elements]) => [namespace, elements.keys()] as const))

/**
 * E.g. `'age_over_18', 'age_over_21', 'age_over_65' in namespace 'org.iso.18013.5.1'`.
 */
export const describeAgeOverLimitViolations = (violations: Array<AgeOverLimitViolation>) =>
  violations
    .map(
      ({ namespace, ageOverIdentifiers }) =>
        `${ageOverIdentifiers.map((elementIdentifier) => `'${elementIdentifier}'`).join(', ')} in namespace '${namespace}'`
    )
    .join(' and ')

/**
 * Report through `onCheck` whether every doc request of `deviceRequest` requests at most two
 * `age_over_NN` elements per namespace (18013-5 7.2.5).
 */
export const verifyAgeOverRequestLimit = (deviceRequest: DeviceRequest, onCheck: VerificationCallback) => {
  const reasons = deviceRequest.docRequests.flatMap((docRequest, docRequestIndex) => {
    const violations = findAgeOverRequestLimitViolations(docRequest.itemsRequest.namespaces)
    return violations.length === 0
      ? []
      : [`Doc request ${docRequestIndex} requests ${describeAgeOverLimitViolations(violations)}`]
  })

  onCheck({
    status: reasons.length === 0 ? 'PASSED' : 'FAILED',
    category: 'DOCUMENT_FORMAT',
    check: `Device request must not request more than ${maximumAgeOverRequests} age_over_NN elements per namespace`,
    reason: reasons.length === 0 ? undefined : reasons.join('; '),
  })
}
