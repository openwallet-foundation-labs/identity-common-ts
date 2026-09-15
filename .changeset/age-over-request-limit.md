---
'@owf/mdoc': minor
---

Enforce the `age_over_NN` limit of ISO/IEC 18013-5 7.2.5, "an mDL reader shall not request more than two age_over_NN data elements", counted per namespace:

- `ItemsRequest.create`, and therefore `IsoMdocDcApi.createRequest`, throws an `AgeOverLimitExceededError` when more than two are requested in a namespace. A decoded request is not checked, so that a holder can report it.
- `Holder.verifyDeviceRequest` and `IsoMdocDcApi.parseRequest` report the limit through the verification callback, so with the default callback a request for more than two throws a `VerificationError`.
- `Holder.matchDeviceRequest` does not match any credential against a doc request for more than two. The doc request fails with `invalidDocRequest: { failure: 'ageOverLimitExceeded', reason }` and empty `failedCredentials`.
- `DeviceResponse.createWithDeviceRequest` throws an `AgeOverLimitExceededError` when a document would disclose more than two distinct age attestations in a namespace. Only what is disclosed counts, so a holder can still answer such a request by selecting at most two of them through `elements`.
