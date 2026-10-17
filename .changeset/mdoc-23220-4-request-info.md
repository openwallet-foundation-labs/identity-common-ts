---
"@owf/mdoc": minor
---

Read and write the request information of ISO/IEC TS 23220-4 7.2.1, which the second edition of ISO/IEC 18013-5 takes up: `ItemsRequest.requestInfo` (`DocRequestInfo`: `AlternativeDataElementsSet`s, issuer identifiers, `uniqueDocSetRequired`, `maximumResponseSize`) and `DeviceRequest.deviceRequestInfo` (`DeviceRequestInfo`: `UseCase`s and their document sets). Unknown keys are ignored and kept, nested ones included, so a request carrying either still re-encodes byte for byte. An invalid value in a known key, or a document set pointing past the doc requests, fails decoding.
