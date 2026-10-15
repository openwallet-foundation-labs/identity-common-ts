---
"@owf/mdoc": minor
---

Match the request information of ISO/IEC TS 23220-4 7.2.1, holder side (`Holder.matchDeviceRequest`) and verifier side (`matchDeviceRequest`, `Verifier.verifyDeviceResponse`):

- alternative data elements: a requested element that is missing is answered by the first alternative set that is all there, reported as `alternativeElements` on the claim and disclosed whole by `Holder.createDeviceResponseForDeviceRequest`
- issuer identifiers: an mdoc only answers a doc request that names issuers when a certificate in its x5chain has one of them as authority or subject key identifier, reported as `issuer` on the credential or document match
- use cases: a device request that carries them succeeds when every mandatory use case and at least one use case have a document set whose doc requests are all satisfied, reported as `useCases` (with `docRequestsAsAlternatives: true`); `treatAmbiguousMultipleDocRequestsAsAlternatives` then does not apply
