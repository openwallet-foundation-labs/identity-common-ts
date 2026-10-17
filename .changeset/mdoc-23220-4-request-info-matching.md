---
"@owf/mdoc": minor
---

Match the request information of ISO/IEC TS 23220-4 7.2.1, which the second edition of ISO/IEC 18013-5 takes up, holder side (`Holder.matchDeviceRequest`, `Holder.createDeviceResponseForDeviceRequest`) and verifier side (`matchDeviceRequest`, `Verifier.verifyDeviceResponse`).

Breaking: a device request is now always matched by use cases. `docRequestsAsAlternatives` is replaced by `useCasesSource` and `useCases`, which every match result carries. Without a `deviceRequestInfo`, the doc requests are one mandatory use case (`'allDocRequests'`, the default), or one optional use case each with `treatAmbiguousMultipleDocRequestsAsAlternatives` (`'eachDocRequest'`). A match succeeds when every mandatory use case and at least one use case are satisfied.

- use cases: each `UseCaseMatch` lists every document set whose doc requests are all satisfied (`documentSets`), for the holder to pick one
- alternative data elements: a requested element is answered by itself or by one of its alternative sets, and the claim lists every option (`options`), in order of preference; the holder can disclose another one than the first with `alternatives` on the document it creates
- issuer identifiers: an mdoc only answers a doc request that names issuers when a certificate in its x5chain has one of them as authority or subject key identifier, reported as `issuer` on the credential or document match
- `uniqueDocSetRequired`: the verifier fails a doc request that more than one document satisfies
- `Holder.createDeviceResponseForDeviceRequest` throws an `UnsatisfiedDeviceRequestError` for a document of an issuer the doc request does not name, a second document for a doc request with `uniqueDocSetRequired`, or a mandatory use case without a document for each doc request of one of its document sets
