---
'@owf/mdoc': minor
---

`DeviceResponse.createWithDeviceRequest` and `IsoMdocDcApi.createResponse` select the elements to disclose the same way `Holder.matchDeviceRequest` matches a credential:

- A requested element the issuer did not sign, but that the device key is authorized for, is disclosed through the `deviceNamespaces` of the document. Before, every requested element had to be issuer-signed.
- A document can pass `elements` to disclose only some of the requested elements, for instance leaving out the ones the user declined to share. This applies to issuer-signed and device-signed elements alike: only the values in `deviceNamespaces` of selected requested elements are disclosed and authenticated.
- A requested element that cannot be disclosed throws a `MissingRequestedElementError`, and selecting an element the doc request does not ask for throws an `InvalidElementSelectionError`.
- Two `age_over_NN` requests answered with the same age attestation (18013-5 7.2.5) have to be selected together or left out together, as leaving out only one would still disclose its answer. Selecting only one throws an `InvalidElementSelectionError`. `disclosedElementIdentifier` on the claims of `Holder.matchDeviceRequest` shows which requests share an attestation.
- A credential whose MSO docType is not the docType of the doc request it answers throws a `DocTypeMismatchError`, instead of producing a document every reader rejects.

`limitDisclosureToDeviceRequestNameSpaces` is removed. Use `DeviceResponse.createWithDeviceRequest`, with `elements` to disclose a subset of the requested elements.
