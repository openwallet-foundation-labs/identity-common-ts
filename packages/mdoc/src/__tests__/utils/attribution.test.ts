import { describe, expect, test } from 'vitest'
import { createAttribution, type DocRequestCandidates } from '../../utils/attribution'

const docRequest = (
  docRequestIndex: number,
  options: { unique?: boolean; candidates: Array<number>; valid?: Array<number> }
): DocRequestCandidates => ({
  docRequestIndex,
  uniqueDocSetRequired: options.unique ?? false,
  candidateDocuments: options.candidates,
  validDocuments: options.valid ?? options.candidates,
})

describe('createAttribution', () => {
  test('a third document for two doc requests that take one each is too many', () => {
    const attribution = createAttribution([
      docRequest(0, { unique: true, candidates: [0, 1, 2] }),
      docRequest(1, { unique: true, candidates: [0, 1, 2] }),
    ])

    expect(attribution.excess).toStrictEqual({ documentIndexes: [0, 1, 2], docRequestIndexes: [0, 1] })
    expect(attribution.canAnswer([0])).toBe(false)
  })

  test('the documents too many are every document an alternating path reaches', () => {
    // Document 2 is left over, and takes doc request 1 from document 1, which takes doc request 0 from document 0.
    const attribution = createAttribution([
      docRequest(0, { unique: true, candidates: [0, 1] }),
      docRequest(1, { unique: true, candidates: [1, 2] }),
    ])

    expect(attribution.excess).toStrictEqual({ documentIndexes: [0, 1, 2], docRequestIndexes: [0, 1] })
  })

  test('a doc request that already has documents too many does not take another', () => {
    // Document 2 may answer doc request 0, which fails, so it has to take doc request 1, which it does
    // not satisfy.
    const attribution = createAttribution([
      docRequest(0, { unique: true, candidates: [0, 1, 2] }),
      docRequest(1, { unique: true, candidates: [2, 3], valid: [3] }),
      docRequest(2, { candidates: [3] }),
    ])

    expect(attribution.excess).toStrictEqual({ documentIndexes: [0, 1], docRequestIndexes: [0] })
    expect(attribution.canAnswer([1])).toBe(false)
    expect(attribution.canAnswer([2])).toBe(true)
  })

  test('a doc request without uniqueDocSetRequired takes the documents too many', () => {
    const attribution = createAttribution([
      docRequest(0, { unique: true, candidates: [0, 1, 2] }),
      docRequest(1, { candidates: [0, 1, 2] }),
    ])

    expect(attribution.excess).toStrictEqual({ documentIndexes: [], docRequestIndexes: [] })
    expect(attribution.canAnswer([0, 1])).toBe(true)
  })

  test('two doc requests can each be answered, but not together', () => {
    // Document 0 satisfies both, document 1 neither, and document 1 needs one of them to itself.
    const attribution = createAttribution([
      docRequest(0, { unique: true, candidates: [0, 1], valid: [0] }),
      docRequest(1, { unique: true, candidates: [0, 1], valid: [0] }),
    ])

    expect(attribution.excess).toStrictEqual({ documentIndexes: [], docRequestIndexes: [] })
    expect(attribution.canAnswer([0])).toBe(true)
    expect(attribution.canAnswer([1])).toBe(true)
    expect(attribution.canAnswer([0, 1])).toBe(false)
  })

  test('one document can answer two doc requests that take one each', () => {
    const attribution = createAttribution([
      docRequest(0, { unique: true, candidates: [0] }),
      docRequest(1, { unique: true, candidates: [0] }),
    ])

    expect(attribution.canAnswer([0, 1])).toBe(true)
    expect(attribution.answer([0, 1])).toStrictEqual(
      new Map([
        [0, [0]],
        [1, [0]],
      ])
    )
  })

  test('agrees with a brute force search, whatever the order of the documents', () => {
    // mulberry32, so that the cases are spread out.
    let seed = 3
    const random = (n: number) => {
      seed = (seed + 0x6d2b79f5) | 0
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
      return Math.floor((((t ^ (t >>> 14)) >>> 0) / 4294967296) * n)
    }

    // The cases have to cover documents too many and doc requests not answered together.
    const covered = { excess: 0, notTogether: 0 }

    for (let iteration = 0; iteration < 4000; iteration++) {
      const documentCount = random(9)
      const docRequests = Array.from({ length: 1 + random(5) }, (_, docRequestIndex) => {
        const candidates = Array.from({ length: documentCount }, (_, documentIndex) => documentIndex).filter(() =>
          random(2)
        )
        return docRequest(docRequestIndex, {
          unique: random(3) > 0,
          candidates,
          valid: candidates.filter(() => random(2)),
        })
      })
      const attribution = createAttribution(docRequests)

      // The most documents of `documents` that each get a doc request with uniqueDocSetRequired to
      // itself, among those `allowed` gives it.
      const placed = (
        documents: Array<number>,
        allowed: (documentIndex: number, docRequestIndex: number) => boolean,
        taken = new Set<number>()
      ): number => {
        const [first, ...rest] = documents
        if (first === undefined) return 0
        let most = placed(rest, allowed, taken)
        for (const { docRequestIndex, uniqueDocSetRequired, candidateDocuments } of docRequests) {
          if (!uniqueDocSetRequired || taken.has(docRequestIndex) || !candidateDocuments.includes(first)) continue
          if (!allowed(first, docRequestIndex)) continue
          taken.add(docRequestIndex)
          most = Math.max(most, 1 + placed(rest, allowed, taken))
          taken.delete(docRequestIndex)
        }
        return most
      }
      const everywhere = () => true
      const onlyUnique = Array.from({ length: documentCount }, (_, documentIndex) => documentIndex).filter(
        (documentIndex) => {
          const candidateOf = docRequests.filter(({ candidateDocuments }) => candidateDocuments.includes(documentIndex))
          return candidateOf.length > 0 && candidateOf.every(({ uniqueDocSetRequired }) => uniqueDocSetRequired)
        }
      )

      // A document is too many when some way of placing as many documents as possible leaves it out,
      // and so are the doc requests it may answer.
      const most = placed(onlyUnique, everywhere)
      const excessDocuments = new Set(
        onlyUnique.filter(
          (documentIndex) =>
            placed(
              onlyUnique.filter((other) => other !== documentIndex),
              everywhere
            ) === most
        )
      )
      const excessDocRequests = new Set(
        docRequests
          .filter(({ candidateDocuments }) =>
            candidateDocuments.some((documentIndex) => excessDocuments.has(documentIndex))
          )
          .map(({ docRequestIndex }) => docRequestIndex)
      )
      expect(new Set(attribution.excess.documentIndexes)).toStrictEqual(excessDocuments)
      expect(new Set(attribution.excess.docRequestIndexes)).toStrictEqual(excessDocRequests)
      if (excessDocuments.size > 0) covered.excess++

      const rest = onlyUnique.filter((documentIndex) => !excessDocuments.has(documentIndex))
      let notTogether = false
      for (let mask = 0; mask < 1 << docRequests.length; mask++) {
        const required = docRequests.filter((_, index) => mask & (1 << index)).map((d) => d.docRequestIndex)
        const eachSatisfied = required.every(
          (index) => !excessDocRequests.has(index) && (docRequests[index]?.validDocuments.length ?? 0) > 0
        )
        const expected =
          eachSatisfied &&
          placed(
            rest,
            (documentIndex, docRequestIndex) =>
              !excessDocRequests.has(docRequestIndex) &&
              (!required.includes(docRequestIndex) ||
                (docRequests[docRequestIndex]?.validDocuments.includes(documentIndex) ?? false))
          ) === rest.length
        expect(attribution.canAnswer(required)).toBe(expected)
        if (eachSatisfied && !expected && required.every((index) => attribution.canAnswer([index]))) {
          notTogether = true
        }
      }

      if (notTogether) covered.notTogether++

      // The same documents in reverse order give the same answers.
      const last = documentCount - 1
      const reversed = createAttribution(
        docRequests.map((d) => ({
          ...d,
          candidateDocuments: d.candidateDocuments.map((index) => last - index).sort((a, b) => a - b),
          validDocuments: d.validDocuments.map((index) => last - index).sort((a, b) => a - b),
        }))
      )
      expect({
        documentIndexes: reversed.excess.documentIndexes.map((index) => last - index).sort((a, b) => a - b),
        docRequestIndexes: reversed.excess.docRequestIndexes,
      }).toStrictEqual(attribution.excess)
      for (let mask = 0; mask < 1 << docRequests.length; mask++) {
        const required = docRequests.filter((_, index) => mask & (1 << index)).map((d) => d.docRequestIndex)
        expect(reversed.canAnswer(required)).toBe(attribution.canAnswer(required))
      }
    }

    expect(covered.excess).toBeGreaterThan(400)
    expect(covered.notTogether).toBeGreaterThan(15)
  })
})
