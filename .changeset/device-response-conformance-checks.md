---
'@owf/mdoc': minor
---

Add four ISO/IEC 18013-5 conformance checks that verification was missing. All four are reported through the existing `onCheck` callback, so `defaultVerificationCallback` now throws on responses that previously passed:

- **Key authorizations (9.1.3.4).** An mdoc "shall only authenticate response data elements in `DeviceNameSpaces` if the key it is using for mdoc authentication is authorized to authenticate these elements in the `KeyAuthorizations` structure in the MSO", and "the mdoc reader shall validate this authorization as part of validating the mdoc authentication". Creating a response only discloses requested device-signed elements the MSO authorizes, including when it has no `keyAuthorizations` at all: a requested element that can only be answered with an unauthorized value throws a `MissingRequestedElementError`, and unrequested values in `deviceNamespaces` are left out.
- **Response status (8.3.2.1.2.3, Table 8).** "If the mdoc returns a status code different from 0, it shall not return any documents".
- **Duplicate element identifiers (8.3.2.1.2.2).** "The mdoc shall not include two or more `IssuerSignedItem` elements with the same `DataElementIdentifier` in a single `NameSpace` and `Document`".
- **Document docType (9.3.1).** The mdoc reader shall "verify that the DocType in the MSO matches the relevant DocType in the Documents structure". This was only checked when a `deviceRequest` was passed to `DeviceResponse.verify`, and is now checked for every document.
