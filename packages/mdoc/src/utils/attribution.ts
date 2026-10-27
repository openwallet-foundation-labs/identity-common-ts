/**
 * A doc request, with the documents of the response that may answer it.
 */
export type DocRequestCandidates = {
  docRequestIndex: number
  uniqueDocSetRequired: boolean
  /**
   * The documents of its docType and of an issuer it accepts, which may answer it with elements left
   * out, as a holder can decline them.
   */
  candidateDocuments: Array<number>
  /**
   * The candidate documents that satisfy it.
   */
  validDocuments: Array<number>
}

/**
 * Works out which document answers which doc request, as a response does not say.
 *
 * A doc request without `uniqueDocSetRequired` is answered by every candidate document. One with it
 * is answered by one document only, and a document can answer several doc requests. A document that
 * only doc requests with `uniqueDocSetRequired` may answer therefore needs one of them to itself: when
 * there are more such documents than doc requests to take them, the response has documents too many,
 * and those doc requests fail (`excess`). They are found with a maximum matching, and are the same
 * whatever the order of the documents (the deficient part of the Dulmage-Mendelsohn decomposition).
 *
 * The other doc requests can be answered together (`canAnswer`) when the documents can be shared
 * out so that each of them with `uniqueDocSetRequired` gets one that satisfies it, while each of
 * those documents still has a doc request of its own.
 */
export const createAttribution = (docRequests: Array<DocRequestCandidates>) => {
  const byIndex = new Map(docRequests.map((docRequest) => [docRequest.docRequestIndex, docRequest]))
  const satisfying = new Map(
    docRequests.map((docRequest) => [docRequest.docRequestIndex, new Set(docRequest.validDocuments)])
  )

  // The documents that only doc requests with `uniqueDocSetRequired` may answer.
  const candidatesOf = new Map<number, Array<number>>()
  for (const { docRequestIndex, candidateDocuments } of docRequests) {
    for (const documentIndex of candidateDocuments) {
      candidatesOf.set(documentIndex, [...(candidatesOf.get(documentIndex) ?? []), docRequestIndex])
    }
  }
  const onlyUnique = Array.from(candidatesOf)
    .filter(([, docRequestIndexes]) => docRequestIndexes.every((index) => byIndex.get(index)?.uniqueDocSetRequired))
    .map(([documentIndex]) => documentIndex)
    .sort((a, b) => a - b)
  const excess = findExcess(
    onlyUnique,
    candidatesOf,
    maximumMatching(onlyUnique, (documentIndex) => candidatesOf.get(documentIndex) ?? [])
  )
  const excessDocRequests = new Set(excess.docRequestIndexes)
  const excessDocuments = new Set(excess.documentIndexes)
  const remaining = onlyUnique.filter((documentIndex) => !excessDocuments.has(documentIndex))

  /**
   * A doc request per remaining document, where each doc request of `required` with
   * `uniqueDocSetRequired` only takes a document that satisfies it. Undefined when there is none.
   */
  const shareOut = (required: ReadonlySet<number>) => {
    const neighbours = (documentIndex: number) =>
      // A doc request in `excess` already fails, and does not take another document.
      (candidatesOf.get(documentIndex) ?? []).filter(
        (docRequestIndex) =>
          !excessDocRequests.has(docRequestIndex) &&
          (!required.has(docRequestIndex) || (satisfying.get(docRequestIndex)?.has(documentIndex) ?? false))
      )
    const taken = maximumMatching(remaining, neighbours)
    return taken.size === remaining.length ? taken : undefined
  }

  /**
   * Whether the doc requests can be answered together: each satisfied by a document, and those with
   * `uniqueDocSetRequired` by a document they can have to themselves when they need one.
   */
  const answers = new Map<string, boolean>()
  const canAnswer = (docRequestIndexes: Array<number>) => {
    const required = new Set(docRequestIndexes)
    const key = Array.from(required)
      .sort((a, b) => a - b)
      .join(',')
    const known = answers.get(key)
    if (known !== undefined) return known
    const answer = canAnswerUncached(required)
    answers.set(key, answer)
    return answer
  }
  const canAnswerUncached = (required: ReadonlySet<number>) => {
    for (const docRequestIndex of required) {
      const docRequest = byIndex.get(docRequestIndex)
      if (!docRequest || docRequest.validDocuments.length === 0 || excessDocRequests.has(docRequestIndex)) return false
    }
    return shareOut(required) !== undefined
  }

  /**
   * Per doc request, the documents it answers when `docRequestIndexes` are answered together.
   */
  const answer = (docRequestIndexes: Array<number>) => {
    const required = new Set(docRequestIndexes)
    const taken = shareOut(required) ?? new Map<number, number>()
    const takes = new Map(Array.from(taken, ([documentIndex, docRequestIndex]) => [docRequestIndex, documentIndex]))

    const byDocRequest = new Map<number, Array<number>>()
    for (const docRequest of docRequests) {
      const { docRequestIndex, uniqueDocSetRequired, candidateDocuments, validDocuments } = docRequest
      if (!uniqueDocSetRequired) {
        byDocRequest.set(docRequestIndex, candidateDocuments)
        continue
      }
      if (excessDocRequests.has(docRequestIndex)) {
        byDocRequest.set(docRequestIndex, [])
        continue
      }
      // A document of its own, or else one it shares with another doc request.
      const documentIndex = takes.get(docRequestIndex) ?? validDocuments[0]
      byDocRequest.set(docRequestIndex, documentIndex === undefined ? [] : [documentIndex])
    }
    return byDocRequest
  }

  return { excess, canAnswer, answer }
}

/**
 * A maximum matching of `documents` to doc requests (Kuhn's algorithm), as the doc request each
 * matched document takes. O(documents · edges).
 */
const maximumMatching = (documents: Array<number>, neighbours: (documentIndex: number) => Array<number>) => {
  const takenBy = new Map<number, number>()
  const augment = (documentIndex: number, visited: Set<number>): boolean => {
    // A free doc request first, so that documents only move when they have to.
    const free = neighbours(documentIndex).find((docRequestIndex) => !takenBy.has(docRequestIndex))
    if (free !== undefined) {
      takenBy.set(free, documentIndex)
      return true
    }
    for (const docRequestIndex of neighbours(documentIndex)) {
      if (visited.has(docRequestIndex)) continue
      visited.add(docRequestIndex)
      const current = takenBy.get(docRequestIndex)
      if (current !== undefined && augment(current, visited)) {
        takenBy.set(docRequestIndex, documentIndex)
        return true
      }
    }
    return false
  }
  for (const documentIndex of documents) augment(documentIndex, new Set())

  return new Map(Array.from(takenBy, ([docRequestIndex, documentIndex]) => [documentIndex, docRequestIndex]))
}

/**
 * The documents left without a doc request in a maximum matching, with every document an alternating
 * path reaches from them: along a candidate of a document, and back along the document that doc
 * request takes. These are the documents some maximum matching leaves without a doc request, and
 * their candidates are the doc requests with documents too many.
 */
const findExcess = (
  documents: Array<number>,
  candidatesOf: Map<number, Array<number>>,
  matching: Map<number, number>
) => {
  const takes = new Map(Array.from(matching, ([documentIndex, docRequestIndex]) => [docRequestIndex, documentIndex]))

  const queue = documents.filter((documentIndex) => !matching.has(documentIndex))
  const reached = new Set(queue)
  for (let position = 0; position < queue.length; position++) {
    for (const docRequestIndex of candidatesOf.get(queue[position] as number) ?? []) {
      const next = takes.get(docRequestIndex)
      if (next !== undefined && !reached.has(next)) {
        reached.add(next)
        queue.push(next)
      }
    }
  }

  const documentIndexes = Array.from(reached).sort((a, b) => a - b)
  const docRequestIndexes = new Set(documentIndexes.flatMap((documentIndex) => candidatesOf.get(documentIndex) ?? []))
  return { documentIndexes, docRequestIndexes: Array.from(docRequestIndexes).sort((a, b) => a - b) }
}
