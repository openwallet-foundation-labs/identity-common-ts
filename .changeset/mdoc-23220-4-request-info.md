---
"@owf/mdoc": minor
---

Read and write the request information of ISO/IEC TS 23220-4 7.2.1, which the second edition of ISO/IEC 18013-5 takes up: `ItemsRequest.requestInfo` (`DocRequestInfo`: alternative data elements, issuer identifiers, `uniqueDocSetRequired`, `maximumResponseSize`) and `DeviceRequest.deviceRequestInfo` (`DeviceRequestInfo`: use cases and their document sets). A request carrying either still re-encodes byte for byte, and one that does not match the CDDL is kept as received and not returned, rather than failing the request, as the mdoc app is to ignore what it cannot interpret.
