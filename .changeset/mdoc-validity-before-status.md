---
'@owf/mdoc': patch
---

`IssuerAuth.verify`, and with it `IssuerSigned.verify`, `Holder.verifyIssuerSigned`, `DeviceResponse.verify`, `Verifier.verifyDeviceResponse` and `IsoMdocDcApi.verifyResponse`, check the status of an mdoc last. Before, the status list or identifier list of the MSO was fetched before its `validityInfo`, the value digests and the docType of the document were checked, so an expired or not yet valid mdoc made the verifier fetch its status list before rejecting it. Token Status List § 8.3 validates the Referenced Token before its status. A verification callback that does not throw no longer gets a status check, and no list is fetched, for an MSO that failed another check of `IssuerAuth.verify`.
