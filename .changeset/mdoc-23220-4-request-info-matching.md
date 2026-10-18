---
"@owf/mdoc": minor
---

Match the request information of ISO/IEC TS 23220-4 7.2.1, which the second edition of ISO/IEC 18013-5 takes up, holder side (`Holder.matchDeviceRequest`, `Holder.createDeviceResponseForDeviceRequest`) and verifier side (`matchDeviceRequest`, `Verifier.verifyDeviceResponse`).

Breaking: a device request is now always matched by use cases. `docRequestsAsAlternatives` is replaced by `useCasesSource` and `useCases`, which every match result carries. Without a `deviceRequestInfo`, the doc requests are one mandatory use case (`'allDocRequests'`, the default), or one optional use case each with `treatAmbiguousMultipleDocRequestsAsAlternatives` (`'eachDocRequest'`). A match succeeds when every mandatory use case and at least one use case are satisfied.

- use cases: each `UseCaseMatch` lists every document set whose doc requests are all satisfied (`documentSets`), for the holder to pick one, with the doc requests of the use case (`docRequestIndexes`) and its `purposeHints`
- alternative data elements: a requested element is answered by itself or by one of its alternative sets, and the claim lists every option (`options`), in order of preference. A response only discloses an alternative set the holder chooses with `alternatives` on the document it creates, never one that discloses an element it leaves out, and a holder is not offered one that would disclose more than two `age_over_NN` elements in a namespace. The verifier does not report the elements of an alternative set as over-disclosure
- issuer identifiers: an mdoc only answers a doc request that names issuers when a certificate in its chain has one of them as authority key identifier, reported as `issuer` on the credential or document match. `Verifier.verifyDeviceResponse` matches them against the validated chain, as the x5chain is unprotected; `matchDeviceRequest` and `Verifier.matchDeviceRequest` take the validated chains as `issuerCertificateChains`
- `uniqueDocSetRequired`: the verifier fails a doc request that more documents satisfy than one, plus one for each other doc request of its docType
- `Holder.createDeviceResponseForDeviceRequest` throws an `UnsatisfiedDeviceRequestError` for a document of an issuer the doc request does not name, a second document for a doc request with `uniqueDocSetRequired`, a mandatory use case, or every use case, without a document of the docType of each doc request of one of its document sets, or a response larger than the smallest `maximumResponseSize`. Without use cases, which doc requests get a document is not checked, as the iOS DC API presents several doc requests as alternatives
- `IsoMdocDcApi`: `createRequest` takes `requestInfo` per doc request and `deviceRequestInfo`, and `createResponse` takes `alternatives` per document
